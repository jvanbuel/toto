//! Task intake, refinement and tracking (ADR 16). Project side only: this runs in the project's own
//! scheduled job (`toto project sync`), which holds the project's signing key. Contributors' runners
//! never see any of it; they still receive nothing but signed manifests.
//!
//! Connectors are split by direction. An [`Inbound`] reports what arrived (a request, a comment, a
//! command) with the facts it can vouch for (who sent it and how that was checked); it decides
//! nothing. An [`Outbound`] shows a task's state somewhere people look. Core ([`policy`], [`task`],
//! [`sync`]) resolves threads, decides approval, and drives each task through its attempts.

pub mod email;
pub mod git;
pub mod github;
pub mod imap;
pub mod policy;
pub mod projects_v2;
pub mod prompt;
pub mod store;
pub mod sync;
pub mod task;

use crate::Result;
use serde::{Deserialize, Serialize};

/// Something a connector can point at: `github:issue:12`, `github:pr:500`, `github:comment:99`,
/// `mail:<message-id>`, `projects-v2:<item id>`. Tasks keep a list of these as their links.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ItemRef(pub String);

impl ItemRef {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ItemRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The identity of one received item, unique within its connector. Used to never handle the same
/// item twice, and linked onto the task so later replies to it resolve.
pub type ReceivedRef = ItemRef;

/// What a connector saw as "this belongs to": an issue number, `In-Reply-To` and `References`.
/// Core resolves it against the tasks' links; the connector holds no state to do that itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ThreadRef(pub Vec<ItemRef>);

/// Where an inbound left off, opaque to core (a comment id, an IMAP UID) and stored on the state
/// branch between passes.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Cursor(pub serde_json::Value);

/// How the connector checked the sender. `Platform`: the platform authenticated the account (a
/// GitHub login). `Dkim`: the receiving mail provider reported an aligned DKIM pass.
/// `SecretAddress` and `Both` are only ever set by core, after comparing the address tag the
/// connector saw with the sender's configured hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verification {
    None,
    Dkim,
    SecretAddress,
    Both,
    Platform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    /// `github:<login>` or a lower-case mail address.
    pub address: String,
    pub verified: Verification,
    /// A platform fact: the account may push to the repository (GitHub: write, maintain or admin).
    pub maintainer: bool,
    /// SHA-256 (hex) of a secret plus-address tag the mail was sent to, if any. Never the tag itself.
    pub tag_sha256: Option<String>,
}

impl Author {
    pub fn platform(login: &str, maintainer: bool) -> Self {
        Self { address: format!("github:{login}"), verified: Verification::Platform, maintainer, tag_sha256: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    Approve,
    Done,
    Reopen,
    Cancel,
}

impl SignalKind {
    /// `/approve`, `/done`, `/reopen` or `/cancel` on the first line of a comment.
    pub fn from_command(text: &str) -> Option<Self> {
        let first = text.trim_start().lines().next()?.trim();
        match first.split_whitespace().next()? {
            "/approve" => Some(Self::Approve),
            "/done" => Some(Self::Done),
            "/reopen" => Some(Self::Reopen),
            "/cancel" => Some(Self::Cancel),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// No thread: a new task. A thread that resolves to a task: a refinement of it.
    Message { id: ReceivedRef, thread: Option<ThreadRef>, author: Author, subject: Option<String>, body: String },
    /// An explicit state change by a person (or by the platform, such as a merged pull request).
    Signal { id: ReceivedRef, thread: ThreadRef, author: Author, kind: SignalKind },
    /// Something the connector will not report as a message, and why (automated mail, a message
    /// too large to read): core writes it to the sync log so a maintainer can see why nothing
    /// happened.
    Skipped { id: ReceivedRef, from: String, reason: String },
}

impl Received {
    pub fn id(&self) -> &ReceivedRef {
        match self {
            Received::Message { id, .. } | Received::Signal { id, .. } | Received::Skipped { id, .. } => id,
        }
    }
}

/// Where requests and feedback come from.
pub trait Inbound {
    /// Names the cursor file on the state branch; stable across releases.
    fn name(&self) -> &str;
    /// What arrived after `since`, and the cursor to pass next time. Reports facts; never decides.
    /// Items may repeat across passes (a pass can fail after receiving); core ignores repeats.
    fn receive(&self, since: &Cursor) -> Result<(Vec<Received>, Cursor)>;
}

/// Where a task's state is shown. Core skips a publish when the view has not changed since the last
/// one to this outbound, and publishing the same view twice must be a no-op as well.
pub trait Outbound {
    fn name(&self) -> &str;
    /// Shows the task and returns the item it is shown as, which core links to the task.
    fn publish(&self, task: &TaskView) -> Result<Option<ItemRef>>;
    /// Ids this outbound looked up and wants kept on the state branch (`cache/<name>.json`).
    fn cache(&self) -> Option<serde_json::Value> {
        None
    }
    fn restore(&self, _cache: serde_json::Value) {}
}

/// What every board can show about a task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskView {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub state: task::State,
    /// The latest attempt (0 before the first one is posted).
    pub attempt: u32,
    pub attempt_cap: u32,
    /// Sum of `tokens_used` over the accepted results.
    pub tokens_used: u64,
    pub requester: String,
    /// The original request, as received (untrusted text: show it fenced).
    pub request: String,
    /// The latest attempt's output, truncated (untrusted text: show it fenced).
    pub latest_output: Option<String>,
    /// Why the task waits, or how it ended.
    pub note: Option<String>,
    pub pr: Option<u64>,
    /// Task issues of the attempts, in order.
    pub attempt_issues: Vec<u64>,
    pub links: Vec<ItemRef>,
}

impl TaskView {
    /// The `github:issue:<n>` link, if the task has a request issue.
    pub fn request_issue(&self) -> Option<u64> {
        request_issue(&self.links)
    }

    /// A hash of what the view shows, without its links: publishing adds links, and that alone
    /// must not count as a change.
    pub fn fingerprint(&self) -> String {
        let mut v = self.clone();
        v.links.clear();
        crate::archive::sha256_hex(&serde_json::to_vec(&v).unwrap_or_default())
    }
}

pub fn request_issue(links: &[ItemRef]) -> Option<u64> {
    links.iter().find_map(|l| l.as_str().strip_prefix("github:issue:").and_then(|n| n.parse().ok()))
}

#[cfg(test)]
mod tests;
