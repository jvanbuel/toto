//! Tasks and attempts. A task is what people talk about; an attempt is one signed manifest that
//! runners execute. Every change goes through [`Task::apply`], a pure function of the event, so the
//! lifecycle is tested without any connector and a sync pass that fails half way can simply be run
//! again.
//!
//! `Draft → Queued → Running(n) → AwaitingFeedback(n) → Queued (refinement) | Done | Cancelled`.
//! `Draft` means "waiting for approval" (a request or refinement nobody approved yet, or the attempt
//! cap); `Queued` means "approved, the next attempt is to be posted".

use super::{ItemRef, TaskView};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum State {
    Draft,
    Queued,
    Running { attempt: u32 },
    AwaitingFeedback { attempt: u32 },
    Done,
    Cancelled,
}

impl State {
    pub fn is_terminal(&self) -> bool {
        matches!(self, State::Done | State::Cancelled)
    }

    pub fn label(&self) -> &'static str {
        match self {
            State::Draft => "Awaiting approval",
            State::Queued => "Queued",
            State::Running { .. } => "Running",
            State::AwaitingFeedback { .. } => "Awaiting feedback",
            State::Done => "Done",
            State::Cancelled => "Cancelled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Request,
    Refinement,
    Result,
}

/// One entry of a task's conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Turn {
    pub source: ItemRef,
    pub role: Role,
    pub author: String,
    pub text: String,
    /// Requests and refinements only run once approved (by policy, or by a maintainer's `/approve`).
    pub approved: bool,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptResult {
    /// The runner's output, truncated for the state file.
    pub output: String,
    pub tokens_used: u64,
    pub runner: String,
    /// What the project side did with it: `pull request`, `text only`, `no change`, `refused: …`.
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub n: u32,
    /// `<task>-a<n>`: deterministic, so a pass that finds it already posted never posts it again.
    pub manifest_id: String,
    /// The conversation turns `[0, upto)` this attempt was built from.
    pub upto: usize,
    pub issue: Option<u64>,
    pub posted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<AttemptResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub project_id: String,
    pub kind: String,
    pub title: String,
    pub estimate: u64,
    /// Address of whoever asked: `github:<login>` or a mail address.
    pub requester: String,
    #[serde(flatten)]
    pub state: State,
    #[serde(default)]
    pub attempts: Vec<Attempt>,
    #[serde(default)]
    pub conversation: Vec<Turn>,
    #[serde(default)]
    pub links: Vec<ItemRef>,
    #[serde(default)]
    pub pr: Option<u64>,
    #[serde(default)]
    pub tokens_used: u64,
    /// Why the task waits, or how it ended.
    #[serde(default)]
    pub note: Option<String>,
    /// A maintainer's `/approve` lets one attempt past the attempt cap.
    #[serde(default)]
    pub cap_override: bool,
    /// Every received item already applied, so a repeated delivery changes nothing.
    #[serde(default)]
    pub seen: BTreeSet<ItemRef>,
    /// Fingerprint of the view last published to each outbound.
    #[serde(default)]
    pub published: BTreeMap<String, String>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

/// The rules a task needs from the policy.
#[derive(Debug, Clone, Copy)]
pub struct Rules {
    pub attempt_cap: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A refinement, or a comment on a finished task (which reopens it).
    Refine(Turn),
    /// A maintainer approves what is waiting, and one attempt past the cap.
    Approve,
    /// The attempt the task was queued for has been posted.
    Posted { manifest_id: String, issue: Option<u64> },
    /// The project side handled a result for this attempt.
    Result { attempt: u32, result: AttemptResult, pr: Option<u64> },
    Done,
    Cancel,
    Reopen,
    /// Idle for longer than the policy's `stale_days`.
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    PostAttempt { attempt: u32 },
    Publish,
    Close,
}

/// Longest attempt output kept in the state file.
pub const MAX_KEPT_OUTPUT: usize = 8_000;

/// The task id for the item that started it: deterministic, so the same request received twice
/// (a pass that failed before saving) is recognised as the same task.
pub fn task_id_for(source: &ItemRef) -> String {
    format!("t-{}", &crate::archive::sha256_hex(source.as_str().as_bytes())[..10])
}

impl Task {
    /// A new task from its request. Call [`Task::apply`] with no event ([`Task::start`]) to queue
    /// it if the request was approved.
    pub fn new(project_id: &str, request: Turn, kind: &str, title: &str, estimate: u64, note: Option<String>, now: DateTime<Utc>) -> Self {
        Self {
            id: task_id_for(&request.source),
            project_id: project_id.into(),
            kind: kind.into(),
            title: title.into(),
            estimate,
            requester: request.author.clone(),
            state: State::Draft,
            attempts: vec![],
            links: vec![request.source.clone()],
            seen: BTreeSet::from([request.source.clone()]),
            conversation: vec![request],
            pr: None,
            tokens_used: 0,
            note,
            cap_override: false,
            published: BTreeMap::new(),
            created: now,
            updated: now,
        }
    }

    pub fn branch(&self, prefix: &str) -> String {
        format!("{prefix}{}", self.id)
    }

    pub fn manifest_id(&self, n: u32) -> String {
        format!("{}-a{n}", self.id)
    }

    pub fn link(&mut self, item: ItemRef) {
        if !self.links.contains(&item) {
            self.links.push(item);
        }
    }

    pub fn request_issue(&self) -> Option<u64> {
        super::request_issue(&self.links)
    }

    /// Requests and refinements not yet in an attempt.
    pub fn pending(&self) -> impl Iterator<Item = &Turn> {
        let from = self.attempts.last().map_or(0, |a| a.upto);
        self.conversation[from.min(self.conversation.len())..].iter().filter(|t| t.role != Role::Result)
    }

    fn last_attempt(&self) -> u32 {
        self.attempts.last().map_or(0, |a| a.n)
    }

    /// Decides the next step from the state alone: idempotent, so it also recovers a pass that
    /// queued an attempt and failed before posting it.
    pub fn start(&mut self, rules: Rules) -> Vec<Effect> {
        self.advance(rules)
    }

    fn advance(&mut self, rules: Rules) -> Vec<Effect> {
        if self.state.is_terminal() || matches!(self.state, State::Running { .. }) {
            return vec![];
        }
        let pending: Vec<&Turn> = self.pending().collect();
        let n = self.last_attempt();
        let (state, note) = if pending.is_empty() {
            (if n == 0 { State::Draft } else { State::AwaitingFeedback { attempt: n } }, self.note.clone().filter(|_| n == 0))
        } else if pending.iter().any(|t| !t.approved) {
            (State::Draft, Some(self.note.clone().unwrap_or_else(|| "waiting for a maintainer's /approve".into())))
        } else if self.attempts.len() as u32 >= rules.attempt_cap && !self.cap_override {
            (State::Draft, Some(format!("{} attempts made (the cap); a maintainer's /approve allows one more", self.attempts.len())))
        } else {
            (State::Queued, None)
        };
        self.state = state;
        self.note = note;
        if self.state == State::Queued { vec![Effect::PostAttempt { attempt: n + 1 }] } else { vec![] }
    }

    /// Applies one event. Events that do not fit the state (a result for an attempt that is not
    /// running, `/approve` on a finished task) change nothing.
    pub fn apply(&mut self, ev: Event, rules: Rules, now: DateTime<Utc>) -> Result<Vec<Effect>> {
        let before = self.clone();
        let mut effects = vec![];
        match ev {
            Event::Refine(turn) => {
                if !self.seen.insert(turn.source.clone()) {
                    return Ok(vec![]);
                }
                self.link(turn.source.clone());
                if self.state.is_terminal() {
                    self.state = State::Draft; // a comment means it is not done; advance() settles the state
                }
                if !turn.approved {
                    self.note = Some(format!("a refinement from {} waits for a maintainer's /approve", turn.author));
                }
                self.conversation.push(turn);
            }
            Event::Approve => {
                if self.state.is_terminal() {
                    return Ok(vec![]);
                }
                let from = self.attempts.last().map_or(0, |a| a.upto).min(self.conversation.len());
                for t in self.conversation[from..].iter_mut() {
                    t.approved = true;
                }
                self.cap_override = true;
                self.note = None;
            }
            Event::Posted { manifest_id, issue } => {
                let n = self.last_attempt() + 1;
                if self.state != State::Queued || manifest_id != self.manifest_id(n) {
                    return Err(Error::Queue(format!("task {}: posted `{manifest_id}` while {:?}", self.id, self.state)));
                }
                self.attempts.push(Attempt { n, manifest_id, upto: self.conversation.len(), issue, posted_at: now, result: None });
                self.state = State::Running { attempt: n };
                self.cap_override = false;
                self.note = None;
            }
            Event::Result { attempt, mut result, pr } => {
                if self.state != (State::Running { attempt }) {
                    return Ok(vec![]);
                }
                result.output = truncate(&result.output, MAX_KEPT_OUTPUT);
                self.tokens_used += result.tokens_used;
                if let Some(pr) = pr {
                    self.pr = Some(pr);
                    self.link(ItemRef::new(format!("github:pr:{pr}")));
                }
                self.conversation.push(Turn {
                    source: ItemRef::new(format!("result:{}", self.manifest_id(attempt))),
                    role: Role::Result,
                    author: result.runner.clone(),
                    text: result.output.clone(),
                    approved: true,
                    at: now,
                });
                if result.outcome.starts_with("refused") {
                    self.note = Some(format!("attempt {attempt} was {}", result.outcome));
                }
                if let Some(a) = self.attempts.iter_mut().find(|a| a.n == attempt) {
                    a.result = Some(result);
                }
                self.state = State::AwaitingFeedback { attempt };
            }
            Event::Done | Event::Cancel | Event::Stale => {
                if self.state.is_terminal() {
                    return Ok(vec![]);
                }
                if matches!(self.state, State::Running { .. }) && ev == Event::Stale {
                    return Ok(vec![]);
                }
                let (state, note) = match ev {
                    Event::Done => (State::Done, None),
                    Event::Cancel => (State::Cancelled, Some("cancelled".to_string())),
                    _ => (State::Cancelled, Some("closed after no activity".to_string())),
                };
                self.state = state;
                self.note = note;
                effects.push(Effect::Close);
            }
            Event::Reopen => {
                if !self.state.is_terminal() {
                    return Ok(vec![]);
                }
                self.state = State::Draft;
                self.note = None;
            }
        }
        effects.extend(self.advance(rules));
        if *self != before {
            self.updated = now;
            effects.push(Effect::Publish);
        }
        Ok(effects)
    }

    pub fn view(&self, rules: Rules) -> TaskView {
        let request = self.conversation.iter().find(|t| t.role == Role::Request).map(|t| t.text.clone()).unwrap_or_default();
        TaskView {
            id: self.id.clone(),
            title: self.title.clone(),
            kind: self.kind.clone(),
            state: self.state.clone(),
            attempt: self.last_attempt(),
            attempt_cap: rules.attempt_cap,
            tokens_used: self.tokens_used,
            requester: self.requester.clone(),
            request: truncate(&request, 4000),
            latest_output: self.attempts.iter().rev().find_map(|a| a.result.as_ref()).map(|r| truncate(&r.output, 4000)),
            note: self.note.clone(),
            pr: self.pr,
            attempt_issues: self.attempts.iter().filter_map(|a| a.issue).collect(),
            links: self.links.clone(),
        }
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max).collect();
    t.push_str("\n… (truncated)");
    t
}
