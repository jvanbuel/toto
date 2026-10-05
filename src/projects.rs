//! Contributors choose which projects they support (`toto projects add|list|remove`).
//!
//! A project publishes a descriptor, `.toto/project.json`, in its repository: its id, public key, the
//! task kinds it posts and what its tasks ask for. Adding a project reads that descriptor and changes
//! the contributor's own config, nothing else: its key becomes trusted, it gets a share, its queue is
//! added and its kinds are allowed. Anything that widens what a task may do (network rules, project
//! context, command-based MCP servers, remote MCP hosts) stays off unless the contributor accepts it
//! by name. The descriptor is only a convenience; every task is still verified against the key the
//! contributor chose to trust, and the runner's policy decides what runs.

use crate::config::{Config, QueueEndpoint};
use crate::manifest::valid_egress_rule;
use crate::{Error, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::PathBuf;

pub const DESCRIPTOR_PATH: &str = ".toto/project.json";

#[derive(Debug, Clone, Deserialize)]
pub struct Needs {
    /// Egress rules (Omnigent DSL) its tasks may carry.
    #[serde(default)]
    pub network: Vec<String>,
    /// Tasks carry project context: skills, AGENTS.md/CLAUDE.md, `.mcp.json`.
    #[serde(default)]
    pub context: bool,
    /// Tasks use MCP servers that run a command in the sandbox.
    #[serde(default)]
    pub stdio_mcp: bool,
    /// Hosts of remote MCP servers its tasks use.
    #[serde(default)]
    pub mcp_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Descriptor {
    pub version: u32,
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Hex Ed25519 public key tasks are signed with.
    pub public_key: String,
    pub kinds: Vec<String>,
    #[serde(default = "no_needs")]
    pub needs: Needs,
}

fn no_needs() -> Needs {
    Needs { network: vec![], context: false, stdio_mcp: false, mcp_hosts: vec![] }
}

fn ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

impl Descriptor {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let bad = |m: String| Error::Policy(format!("project descriptor: {m}"));
        if bytes.len() > 64 * 1024 {
            return Err(bad("too large".into()));
        }
        let d: Descriptor = serde_json::from_slice(bytes).map_err(|e| bad(e.to_string()))?;
        if d.version != 1 {
            return Err(bad(format!("unsupported version {}", d.version)));
        }
        if !ident(&d.id) {
            return Err(bad(format!("id `{}` must be 1-64 characters of a-z, 0-9, - or _", d.id)));
        }
        if hex::decode(&d.public_key).ok().filter(|b| b.len() == 32).is_none() {
            return Err(bad("public_key must be 32 bytes of hex".into()));
        }
        if d.kinds.is_empty() || d.kinds.iter().any(|k| !ident(k)) {
            return Err(bad("kinds must be a non-empty list of simple names".into()));
        }
        if let Some(r) = d.needs.network.iter().find(|r| !valid_egress_rule(r)) {
            return Err(bad(format!("malformed egress rule `{r}`")));
        }
        if let Some(h) = d.needs.mcp_hosts.iter().find(|h| h.is_empty() || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')) {
            return Err(bad(format!("bad MCP host `{h}`")));
        }
        Ok(d)
    }

    /// Short fingerprint of the key, for the contributor to compare with what the project publishes.
    pub fn fingerprint(&self) -> String {
        self.public_key.chars().take(16).collect()
    }
}

/// What a contributor can accept by name when adding a project.
pub const ACCEPTABLE: [&str; 4] = ["network", "context", "stdio-mcp", "mcp-hosts"];

pub struct AddOptions {
    pub share: u32,
    pub accept: BTreeSet<String>,
    /// File with the contributor's GitHub token (to claim and answer tasks); `None` leaves it unset.
    pub token_file: Option<PathBuf>,
}

/// Adds the project to `cfg`; returns what was granted and what was left off, for the contributor.
pub fn add(cfg: &mut Config, repo: &str, d: &Descriptor, o: &AddOptions) -> Result<Vec<String>> {
    if let Some(a) = o.accept.iter().find(|a| !ACCEPTABLE.contains(&a.as_str())) {
        return Err(Error::Policy(format!("cannot accept `{a}`; choose from {}", ACCEPTABLE.join(", "))));
    }
    if cfg.projects.get(&d.id).is_some_and(|k| *k != d.public_key) {
        return Err(Error::Policy(format!("project `{}` is already configured with a different key; remove it first if you mean to switch", d.id)));
    }
    let mut notes = vec![];
    cfg.projects.insert(d.id.clone(), d.public_key.clone());
    cfg.policy.project_shares.insert(d.id.clone(), o.share.max(1));
    cfg.sources.insert(d.id.clone(), repo.to_string());
    for k in &d.kinds {
        if !cfg.policy.allowed_kinds.contains(k) {
            cfg.policy.allowed_kinds.push(k.clone());
        }
    }
    if !cfg.queues.iter().any(|q| matches!(q, QueueEndpoint::Github { repo: r, .. } if r == repo)) {
        cfg.queues.push(QueueEndpoint::Github { repo: repo.into(), token_file: o.token_file.clone(), label: crate::github_queue::DEFAULT_LABEL.into(), api_url: crate::github_queue::DEFAULT_API.into() });
    }
    let on = |what: &str| o.accept.contains(what);
    let mut gate = |wanted: bool, what: &str, label: String, apply: &mut dyn FnMut(&mut Config)| {
        if !wanted {
            return;
        }
        if on(what) {
            apply(cfg);
            notes.push(format!("granted   {label}"));
        } else {
            notes.push(format!("NOT granted {label} (add `--accept {what}` to allow it); tasks needing it will be refused"));
        }
    };
    gate(!d.needs.network.is_empty(), "network", format!("network access: {}", d.needs.network.join(", ")), &mut |c| {
        for r in &d.needs.network {
            if !c.policy.max_profile.network_allowlist.contains(r) {
                c.policy.max_profile.network_allowlist.push(r.clone());
            }
        }
    });
    gate(d.needs.context, "context", "project context (skills, instructions, MCP config)".into(), &mut |c| c.policy.allow_context = true);
    gate(d.needs.stdio_mcp, "stdio-mcp", "MCP servers that run a command in the sandbox".into(), &mut |c| c.policy.allow_stdio_mcp = true);
    gate(!d.needs.mcp_hosts.is_empty(), "mcp-hosts", format!("remote MCP hosts: {}", d.needs.mcp_hosts.join(", ")), &mut |c| {
        for h in &d.needs.mcp_hosts {
            if !c.policy.allowed_mcp_hosts.contains(h) {
                c.policy.allowed_mcp_hosts.push(h.clone());
            }
        }
    });
    if cfg.queues.iter().any(|q| matches!(q, QueueEndpoint::Github { repo: r, token_file: None, .. } if r == repo)) {
        notes.push("no GitHub token configured for this queue: set `token_file` (a token that may comment on issues) so your runner can claim and answer tasks".into());
    }
    Ok(notes)
}

/// Stops supporting a project: its key, share, source and queue entry go. Kinds and accepted
/// permissions stay in the policy (other projects may use them); the note says so.
pub fn remove(cfg: &mut Config, id: &str) -> Result<String> {
    if cfg.projects.remove(id).is_none() {
        return Err(Error::Policy(format!("project `{id}` is not configured")));
    }
    cfg.policy.project_shares.remove(id);
    let repo = cfg.sources.remove(id);
    if let Some(repo) = repo.filter(|r| !cfg.sources.values().any(|o| o == r)) {
        cfg.queues.retain(|q| !matches!(q, QueueEndpoint::Github { repo: r, .. } if *r == repo));
    }
    Ok("removed; allowed kinds and any permissions you accepted were left in your policy".into())
}

pub fn list(cfg: &Config) -> Vec<String> {
    cfg.projects
        .iter()
        .map(|(id, key)| {
            let share = cfg.policy.project_shares.get(id).copied().unwrap_or(0);
            let from = cfg.sources.get(id).map_or(String::new(), |r| format!("  github:{r}"));
            format!("{id}  key {}…  share {share}{from}", key.chars().take(16).collect::<String>())
        })
        .collect()
}
