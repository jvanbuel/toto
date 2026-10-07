//! Approval policy for intake (ADR 16). Connectors report who sent something and how that was
//! checked; this decides whether it becomes work. A request or refinement runs if a maintainer sent
//! it, or a pre-approved sender within their limits; anything else waits for a maintainer's
//! `/approve` (when it arrived somewhere a maintainer can see it) or is ignored (unknown mail).

use super::task::{Rules, Task};
use super::{Author, SignalKind, Verification};
use crate::manifest::SandboxProfile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn default_attempt_cap() -> u32 {
    5
}
fn default_daily_attempt_cap() -> u32 {
    20
}
fn default_stale_days() -> u32 {
    14
}
fn default_per_day() -> u32 {
    3
}
fn default_tools() -> Vec<String> {
    vec!["omnigent".into()]
}
fn default_output_bytes() -> usize {
    32 * 1024
}
fn default_artifact_bytes() -> u64 {
    4 << 20
}
fn default_format() -> String {
    "text".into()
}

/// What a task of one kind becomes as a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindDefaults {
    /// Tokens an attempt is expected to use; runners check it against their caps.
    pub estimate: u64,
    #[serde(default = "default_tools")]
    pub tool_requirements: Vec<String>,
    #[serde(default)]
    pub sandbox_profile: Option<SandboxProfile>,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default = "default_output_bytes")]
    pub max_output_bytes: usize,
    #[serde(default = "default_artifact_bytes")]
    pub max_artifact_bytes: u64,
}

/// How a sender must be verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verify {
    Dkim,
    SecretAddress,
    Both,
    Platform,
}

/// A pre-approved sender. Each is a credential: whoever controls the mailbox (or learns the secret
/// address, or the GitHub account) can spend donated tokens on the project within these limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sender {
    /// A mail address, or `github:<login>`.
    pub address: String,
    /// Default: `platform` for `github:` senders, `dkim` for mail.
    #[serde(default)]
    pub verify: Option<Verify>,
    /// Kinds this sender may ask for; empty: every configured kind.
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub default_kind: Option<String>,
    /// Largest cost estimate accepted without a maintainer; default: the kind's own estimate.
    #[serde(default)]
    pub max_estimate: Option<u64>,
    /// Requests and refinements accepted per UTC day.
    #[serde(default = "default_per_day")]
    pub per_day: u32,
    /// SHA-256 (hex) of the secret plus-address tag (`toto project secret-address` makes one).
    #[serde(default)]
    pub secret_sha256: Option<String>,
}

impl Sender {
    pub fn verify(&self) -> Verify {
        self.verify.unwrap_or(if self.address.starts_with("github:") { Verify::Platform } else { Verify::Dkim })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntakePolicy {
    #[serde(default = "default_attempt_cap")]
    pub attempt_cap: u32,
    /// Attempts posted per UTC day across the project.
    #[serde(default = "default_daily_attempt_cap")]
    pub daily_attempt_cap: u32,
    /// A task with no activity for this long is closed.
    #[serde(default = "default_stale_days")]
    pub stale_days: u32,
    /// The kind of a request that names none; default: the first kind.
    #[serde(default)]
    pub default_kind: Option<String>,
    #[serde(default)]
    pub kinds: BTreeMap<String, KindDefaults>,
    #[serde(default)]
    pub senders: Vec<Sender>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Accept,
    /// Becomes a task (or a refinement) that waits for a maintainer's `/approve`.
    Hold(String),
    /// Nothing happens; the reason goes to the sync log.
    Ignore(String),
}

/// What a message asks for, as core read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    pub kind: String,
    pub estimate: u64,
    /// Set when the message named a kind that is not configured (the default is used instead).
    pub unknown_kind: Option<String>,
}

impl IntakePolicy {
    pub fn rules(&self) -> Rules {
        Rules { attempt_cap: self.attempt_cap }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.kinds.is_empty() {
            return Err("intake config: define at least one kind under [kinds.<name>]".into());
        }
        for (name, k) in &self.kinds {
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(format!("intake config: kind `{name}`: use letters, digits, `-` and `_`"));
            }
            if k.estimate == 0 {
                return Err(format!("intake config: kind `{name}` needs an estimate above 0"));
            }
            if !matches!(k.format.as_str(), "text" | "json") {
                return Err(format!("intake config: kind `{name}`: format is `text` or `json`"));
            }
        }
        if let Some(d) = &self.default_kind
            && !self.kinds.contains_key(d)
        {
            return Err(format!("intake config: default_kind `{d}` is not a configured kind"));
        }
        if self.attempt_cap == 0 {
            return Err("intake config: attempt_cap must be at least 1".into());
        }
        for s in &self.senders {
            let github = s.address.starts_with("github:");
            if !github && !s.address.contains('@') {
                return Err(format!("intake config: sender `{}` is neither a mail address nor `github:<login>`", s.address));
            }
            if s.address != s.address.to_lowercase() {
                return Err(format!("intake config: sender `{}`: write addresses in lower case", s.address));
            }
            match (github, s.verify()) {
                (true, Verify::Platform) | (false, Verify::Dkim) => {}
                (false, Verify::SecretAddress | Verify::Both) if s.secret_sha256.is_some() => {}
                (false, Verify::SecretAddress | Verify::Both) => return Err(format!("intake config: sender `{}` verifies by secret address but has no secret_sha256", s.address)),
                _ => return Err(format!("intake config: sender `{}`: `{:?}` does not fit this kind of address", s.address, s.verify())),
            }
            if let Some(h) = &s.secret_sha256
                && (h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(format!("intake config: sender `{}`: secret_sha256 must be 64 hex characters", s.address));
            }
            for k in s.kinds.iter().chain(&s.default_kind) {
                if !self.kinds.contains_key(k) {
                    return Err(format!("intake config: sender `{}` names kind `{k}`, which is not configured", s.address));
                }
            }
        }
        Ok(())
    }

    pub fn sender(&self, address: &str) -> Option<&Sender> {
        self.senders.iter().find(|s| s.address == address.to_lowercase())
    }

    pub fn default_kind(&self) -> String {
        self.default_kind.clone().or_else(|| self.kinds.keys().next().cloned()).unwrap_or_default()
    }

    /// The kind and estimate a new request asks for: a `[kind]` tag in the subject or a `Kind`
    /// field in the body, else the sender's default, else the project's; an `Estimate` field in the
    /// body, else the kind's.
    pub fn ask(&self, author: &Author, subject: Option<&str>, body: &str) -> Ask {
        let named = subject.and_then(subject_tag).or_else(|| field(body, "kind"));
        let fallback = self.sender(&author.address).and_then(|s| s.default_kind.clone()).unwrap_or_else(|| self.default_kind());
        let (kind, unknown_kind) = match named {
            Some(k) if self.kinds.contains_key(&k) => (k, None),
            Some(k) => (fallback, Some(k)),
            None => (fallback, None),
        };
        let default = self.kinds.get(&kind).map_or(0, |k| k.estimate);
        let estimate = field(body, "estimate").and_then(|e| e.replace([',', '_', ' '], "").parse().ok()).filter(|e: &u64| *e > 0).unwrap_or(default);
        Ask { kind, estimate, unknown_kind }
    }

    /// The verification core vouches for: the connector's, plus the secret address when the tag it
    /// saw hashes to this sender's configured secret.
    pub fn verification(&self, author: &Author) -> Verification {
        let tag = self.sender(&author.address).and_then(|s| s.secret_sha256.as_deref()).zip(author.tag_sha256.as_deref()).is_some_and(|(want, got)| want.eq_ignore_ascii_case(got));
        match (author.verified, tag) {
            (Verification::Dkim | Verification::Both, true) => Verification::Both,
            (Verification::None | Verification::SecretAddress, true) => Verification::SecretAddress,
            (Verification::SecretAddress, false) => Verification::None,
            (Verification::Both, false) => Verification::Dkim,
            (v, _) => v,
        }
    }

    fn verified_as(&self, author: &Author, want: Verify) -> bool {
        let v = self.verification(author);
        match want {
            Verify::Platform => v == Verification::Platform,
            Verify::Dkim => matches!(v, Verification::Dkim | Verification::Both),
            Verify::SecretAddress => matches!(v, Verification::SecretAddress | Verification::Both),
            Verify::Both => v == Verification::Both,
        }
    }

    pub fn is_maintainer(&self, author: &Author) -> bool {
        author.maintainer && author.verified == Verification::Platform
    }

    /// A pre-approved sender, verified the way their entry requires.
    fn verified_sender(&self, author: &Author) -> Result<Option<&Sender>, String> {
        match self.sender(&author.address) {
            None => Ok(None),
            Some(s) if self.verified_as(author, s.verify()) => Ok(Some(s)),
            Some(s) => Err(format!("{} must be verified by {:?}; this message was {:?}", s.address, s.verify(), self.verification(author))),
        }
    }

    /// A request (new task) or a refinement. `used_today` is how many messages from this sender
    /// were accepted today.
    pub fn decide_message(&self, author: &Author, ask: &Ask, used_today: u32) -> Decision {
        let visible = author.verified == Verification::Platform;
        let hold_or_ignore = |why: String| if visible { Decision::Hold(why) } else { Decision::Ignore(why) };
        if self.is_maintainer(author) {
            return match &ask.unknown_kind {
                Some(k) => Decision::Hold(format!("kind `{k}` is not configured; /approve runs it as `{}`", ask.kind)),
                None => Decision::Accept,
            };
        }
        let sender = match self.verified_sender(author) {
            Ok(Some(s)) => s,
            Ok(None) => return hold_or_ignore(format!("{} is not a maintainer or a pre-approved sender", author.address)),
            Err(why) => return Decision::Ignore(why),
        };
        let max = sender.max_estimate.unwrap_or_else(|| self.kinds.get(&ask.kind).map_or(0, |k| k.estimate));
        let why = if let Some(k) = &ask.unknown_kind {
            Some(format!("kind `{k}` is not configured"))
        } else if !sender.kinds.is_empty() && !sender.kinds.contains(&ask.kind) {
            Some(format!("{} may not ask for `{}`", sender.address, ask.kind))
        } else if ask.estimate > max {
            Some(format!("estimate {} is above {}'s limit of {max}", ask.estimate, sender.address))
        } else if used_today >= sender.per_day {
            Some(format!("{} reached their limit of {} per day", sender.address, sender.per_day))
        } else {
            None
        };
        // A verified sender over a limit can still be seen and approved: their mail is mirrored to
        // an issue. Only unknown or unverified mail is dropped.
        match why {
            None => Decision::Accept,
            Some(why) => Decision::Hold(format!("{why}; a maintainer's /approve runs it")),
        }
    }

    /// `/approve` is for maintainers; `done`, `cancel` and `reopen` also for whoever asked.
    pub fn decide_signal(&self, author: &Author, kind: SignalKind, task: &Task) -> Decision {
        if self.is_maintainer(author) {
            return Decision::Accept;
        }
        let requester = author.address == task.requester && (author.verified == Verification::Platform || self.verified_sender(author).is_ok_and(|s| s.is_some()));
        match kind {
            SignalKind::Approve => Decision::Ignore(format!("{} may not approve: only maintainers can", author.address)),
            _ if requester => Decision::Accept,
            _ => Decision::Ignore(format!("{} is neither a maintainer nor who asked", author.address)),
        }
    }
}

/// `[docs] Fix the README` → `docs`.
pub fn subject_tag(subject: &str) -> Option<String> {
    let s = strip_reply_prefixes(subject);
    let tag = s.strip_prefix('[')?.split_once(']')?.0.trim().to_lowercase();
    (!tag.is_empty()).then_some(tag)
}

/// The subject without `Re:`/`Fwd:` prefixes and without a leading `[kind]` tag.
pub fn clean_title(subject: &str) -> String {
    let s = strip_reply_prefixes(subject);
    let s = match s.strip_prefix('[').and_then(|r| r.split_once(']')) {
        Some((_, rest)) => rest.trim(),
        None => s,
    };
    s.chars().take(120).collect()
}

fn strip_reply_prefixes(mut s: &str) -> &str {
    loop {
        let t = s.trim_start();
        let lower = t.to_lowercase();
        match ["re:", "fwd:", "fw:", "aw:"].iter().find(|p| lower.starts_with(*p)) {
            Some(p) => s = &t[p.len()..],
            None => return t,
        }
    }
}

/// A field from an issue form (`### Kind` followed by its value) or a `Kind: value` line.
pub fn field(body: &str, name: &str) -> Option<String> {
    let lines: Vec<&str> = body.lines().map(str::trim).collect();
    for (i, l) in lines.iter().enumerate() {
        if let Some(h) = l.strip_prefix("###")
            && h.trim().eq_ignore_ascii_case(name)
        {
            let v = lines[i + 1..].iter().find(|v| !v.is_empty())?;
            return (!v.starts_with("###") && *v != "_No response_").then(|| v.to_lowercase());
        }
        if let Some((k, v)) = l.split_once(':')
            && k.trim().eq_ignore_ascii_case(name)
            && !v.trim().is_empty()
        {
            return Some(v.trim().to_lowercase());
        }
    }
    None
}
