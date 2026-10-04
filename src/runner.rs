//! Task lifecycle (design doc, "Task lifecycle"): one `tick` takes at most one task.

use crate::audit::{AuditEntry, AuditLog};
use crate::harness::Harness;
use crate::manifest::{TaskManifest, TrustedProjects};
use crate::meter::UsageMeter;
use crate::policy::Policy;
use crate::queue::QueueClient;
use crate::result::TaskResult;
use crate::sandbox::Sandbox;
use crate::{Error, Result};
use chrono::{DateTime, Local};
use ed25519_dalek::SigningKey;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Review-before-submit hook; the TUI implements it, tests use closures.
pub trait Reviewer: Send {
    fn approve(&self, task: &TaskManifest, result: &TaskResult) -> bool;
}

impl<F: Fn(&TaskManifest, &TaskResult) -> bool + Send> Reviewer for F {
    fn approve(&self, task: &TaskManifest, result: &TaskResult) -> bool {
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

        // 2-3. Candidates must verify (ADR 3) and pass policy before we claim anything.
        let mut ok = Vec::new();
        for m in self.queue.available()? {
            if self.refused.contains(&m.id) {
                continue;
            }
            let supported = if m.context.is_empty() || self.harness.supports_context() { Ok(()) } else { Err(Error::Policy("harness cannot deliver skills or MCP servers".into())) };
            match self.trusted.verify(&m).and_then(|_| self.policy.admit(&m, used_today, now)).and_then(|_| supported) {
                Ok(()) => ok.push(m),
                Err(e) => {
                    self.log(&m, "rejected", &e, 0, now)?;
                    self.refused.insert(m.id.clone());
                }
            }
        }
        let Some(task) = self.policy.choose(&ok, &per_project).cloned() else { return Ok(Tick::Idle) };
        let id = self.runner_id();
        if self.queue.claim(&task.id, &id, self.lease).is_err() {
            return Ok(Tick::Idle); // lost the race; try again next tick
        }

        *self.current_lease.lock().unwrap() = Some(task.id.clone());
        let out = self.run_claimed(task, &id, now);
        *self.current_lease.lock().unwrap() = None;
        if let Ok(Tick::Dropped(t)) = &out {
            // Never retry a task this runner already aborted or failed: it would burn tokens in a loop.
            self.refused.insert(t.clone());
        }
        out
    }

    fn run_claimed(&mut self, task: TaskManifest, id: &str, now: DateTime<Local>) -> Result<Tick> {
        let id = id.to_string();
        // 4-7. Sandboxed run under the usage meter, then package.
        let mut meter = UsageMeter::new(task.cost_estimate, self.policy.abort_margin_pct);
        let ws = self.sandbox.create(&task, &task.sandbox_profile)?;
        let run = self.harness.run(&task, &ws, &mut meter);
        self.sandbox.destroy(ws)?;
        let packaged = run.and_then(|out| TaskResult::package(&task.id, out, meter.used(), &task.output_schema, &self.key));
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
            self.log(&task, "rejected", Error::ReviewRejected, result.tokens_used, now)?;
            self.queue.release(&task.id, &id)?;
            return Ok(Tick::Dropped(task.id));
        }

        // 9. Submit and record.
        self.queue.submit(&result)?;
        let detail = if task.context.is_empty() { result.output_hash.clone() } else { format!("{} {}", result.output_hash, task.context.summary()) };
        self.log(&task, "submitted", detail, result.tokens_used, now)?;
        Ok(Tick::Submitted(task.id))
    }
}
