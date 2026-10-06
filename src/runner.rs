//! Task lifecycle (design doc, "Task lifecycle"): one `tick` takes at most one task.

use crate::audit::{AuditEntry, AuditLog};
use crate::harness::Harness;
use crate::manifest::{TaskManifest, TrustedProjects};
use crate::meter::UsageMeter;
use crate::policy::Policy;
use crate::queue::QueueClient;
use crate::result::SignedResult;
use crate::sandbox::Sandbox;
use crate::{Error, Result};
use chrono::{DateTime, Local};
use ed25519_dalek::SigningKey;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Review-before-submit hook; the TUI implements it, tests use closures.
pub trait Reviewer: Send {
    fn approve(&self, task: &TaskManifest, result: &SignedResult) -> bool;
}

impl<F: Fn(&TaskManifest, &SignedResult) -> bool + Send> Reviewer for F {
    fn approve(&self, task: &TaskManifest, result: &SignedResult) -> bool {
        self(task, result)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Tick {
    /// Nothing claimable that policy allows.
    Idle,
    Submitted(String),
    /// Claimed but not submitted (aborted, failed or declined in review).
    Dropped(String),
}

pub struct Runner<Q, H, S, R> {
    pub policy: Policy,
    pub trusted: TrustedProjects,
    pub key: SigningKey,
    pub queue: Q,
    pub harness: H,
    pub sandbox: S,
    pub reviewer: R,
    pub audit: AuditLog,
    pub lease: Duration,
    /// Task ids already refused, so a bad task is logged once rather than every tick.
    refused: HashSet<String>,
    /// Id of the task currently leased, shared with the daemon's heartbeat task.
    pub current_lease: Arc<Mutex<Option<String>>>,
}

#[allow(clippy::too_many_arguments)]
impl<Q: QueueClient, H: Harness, S: Sandbox, R: Reviewer> Runner<Q, H, S, R> {
    pub fn new(policy: Policy, trusted: TrustedProjects, key: SigningKey, queue: Q, harness: H, sandbox: S, reviewer: R, audit: AuditLog) -> Self {
        Self { policy, trusted, key, queue, harness, sandbox, reviewer, audit, lease: Duration::from_secs(900), refused: HashSet::new(), current_lease: Arc::default() }
    }

    pub fn runner_id(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    fn log(&self, t: &TaskManifest, outcome: &str, detail: impl ToString, tokens: u64, now: DateTime<Local>) -> Result<()> {
        self.audit.append(&AuditEntry { ts: now, task_id: t.id.clone(), project_id: t.project_id.clone(), outcome: outcome.into(), detail: detail.to_string(), tokens })
    }

    pub fn tick(&mut self, now: DateTime<Local>) -> Result<Tick> {
        // 1. Policy: cap and time window.
        if self.policy.in_quiet_hours(now) {
            return Ok(Tick::Idle);
        }
        let per_project = self.audit.usage_on(now.date_naive())?;
        let used_today: u64 = per_project.values().sum();

        // 2-3. Candidates must verify (ADR 3) and pass policy before we claim anything. Refusals
        // are remembered by a hash of the signed bytes, never by a task id the sender chose.
        let mut ok: Vec<(String, TaskManifest)> = Vec::new();
        for env in self.queue.available()? {
            let key = env.payload_bytes().map(|b| crate::archive::sha256_hex(&b)).unwrap_or_default();
            if self.refused.contains(&key) {
                continue;
            }
            let verdict = self.trusted.verify(&env).and_then(|m| {
                self.policy.admit(&m, used_today, now)?;
                Ok(m)
            });
            match verdict {
                Ok(m) => ok.push((key, m)),
                Err(e) => {
                    // Unverified fields are only labels for the log here.
                    let claimed = crate::manifest::peek_manifest(&env).ok();
                    let (task_id, project_id) = claimed.map_or(("?".into(), "?".into()), |m| (m.id, m.project_id));
                    self.audit.append(&AuditEntry { ts: now, task_id, project_id, outcome: "rejected".into(), detail: e.to_string(), tokens: 0 })?;
                    self.refused.insert(key);
                }
            }
        }
        let manifests: Vec<TaskManifest> = ok.iter().map(|(_, m)| m.clone()).collect();
        let Some(task) = self.policy.choose(&manifests, &per_project).cloned() else { return Ok(Tick::Idle) };
        let key = ok.iter().find(|(_, m)| m.id == task.id && m.project_id == task.project_id).map(|(k, _)| k.clone()).unwrap_or_default();
        let id = self.runner_id();
        if self.queue.claim(&task.id, &id, self.lease).is_err() {
            return Ok(Tick::Idle); // lost the race; try again next tick
        }

        *self.current_lease.lock().unwrap() = Some(task.id.clone());
        let out = self.run_claimed(task, &id, now);
        *self.current_lease.lock().unwrap() = None;
        if let Ok(Tick::Dropped(_)) = &out {
            // Never retry a task this runner already aborted or failed: it would burn tokens in a loop.
            self.refused.insert(key);
        }
        out
    }

    /// Fetches the task's input bundle, checks it against the signed hash and unpacks it into the
    /// workspace. An all-zero hash means the task has no inputs.
    fn prepare_inputs(&self, task: &TaskManifest, ws: &crate::sandbox::Workspace) -> Result<()> {
        if task.inputs.len() != 64 || !task.inputs.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Verify("inputs must be a 64-character hex SHA-256".into()));
        }
        if task.inputs.chars().all(|c| c == '0') {
            return Ok(());
        }
        let bundle = self.queue.bundle(&task.inputs)?.ok_or_else(|| Error::Queue("input bundle not available".into()))?;
        if bundle.len() as u64 > self.policy.max_input_bytes {
            return Err(Error::Policy(format!("input bundle is {} bytes, limit {}", bundle.len(), self.policy.max_input_bytes)));
        }
        if crate::archive::sha256_hex(&bundle) != task.inputs {
            return Err(Error::Verify("input bundle does not match the signed hash".into()));
        }
        self.sandbox.put_inputs(ws, &bundle, self.policy.max_input_bytes)
    }

    /// Changed files as an archive, only when the task's schema allows artifacts and there are any.
    fn collect_artifacts(&self, task: &TaskManifest, ws: &crate::sandbox::Workspace) -> Result<Option<Vec<u8>>> {
        let max = task.output_schema.max_artifact_bytes;
        if max == 0 {
            return Ok(None);
        }
        let bytes = self.sandbox.collect_outputs(ws, max)?;
        let any = !crate::archive::from_bytes(&bytes, crate::archive::Limits::new(max)).map_err(Error::Sandbox)?.is_empty();
        Ok(any.then_some(bytes))
    }

    fn run_claimed(&mut self, task: TaskManifest, id: &str, now: DateTime<Local>) -> Result<Tick> {
        let id = id.to_string();
        // 4-7. Sandboxed run under the usage meter, then package.
        let mut meter = UsageMeter::new(task.cost_estimate, self.policy.abort_margin_pct);
        let ws = self.sandbox.create(&task, &task.sandbox_profile)?;
        let run = self.prepare_inputs(&task, &ws).and_then(|_| self.harness.run(&task, &ws, &mut meter));
        let artifacts = if run.is_ok() { self.collect_artifacts(&task, &ws) } else { Ok(None) };
        self.sandbox.destroy(ws)?;
        let packaged = run.and_then(|out| SignedResult::package(&task.id, out, meter.used(), &task.output_schema, &self.key, artifacts?));
        let result = match packaged {
            Ok(r) => r,
            Err(e) => {
                let outcome = if matches!(e, Error::Meter { .. }) { "aborted" } else { "failed" };
                self.log(&task, outcome, &e, meter.used(), now)?;
                self.queue.release(&task.id, &id)?;
                return Ok(Tick::Dropped(task.id));
            }
        };

        // 8. Optional review before anything leaves the machine.
        if self.policy.review_before_submit && !self.reviewer.approve(&task, &result) {
            self.log(&task, "rejected", Error::ReviewRejected, meter.used(), now)?;
            self.queue.release(&task.id, &id)?;
            return Ok(Tick::Dropped(task.id));
        }

        // 9. Submit and record.
        self.queue.submit(&result)?;
        self.log(&task, "submitted", result.open()?.output_hash, meter.used(), now)?;
        Ok(Tick::Submitted(task.id))
    }
}
