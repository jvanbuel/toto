//! Policy engine: the contributor's consent (ADR 4: source of truth for caps and shares).

use crate::context::ProjectContext;
use crate::manifest::{SandboxProfile, TaskManifest};
use crate::{Error, Result};
use chrono::{DateTime, Local, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Hard cap on tokens donated per local day.
    pub daily_token_cap: u64,
    /// Allowed projects and their resource shares (relative weights).
    pub project_shares: BTreeMap<String, u32>,
    /// Allowed task kinds; empty allows none.
    pub allowed_kinds: Vec<String>,
    /// Local hours `[start, end)` during which no work is taken; may wrap midnight.
    #[serde(default)]
    pub quiet_hours: Option<(u32, u32)>,
    #[serde(default)]
    pub review_before_submit: bool,
    /// Tasks may only request profiles within these limits (contributors loosen per project).
    #[serde(default)]
    pub max_profile: SandboxProfile,
    /// A task is aborted once it exceeds its estimate by this percentage.
    #[serde(default = "default_margin")]
    pub abort_margin_pct: u64,
    /// Tools this runner can drive (e.g. `claude-code`, `api-key`).
    pub available_tools: Vec<String>,
    /// Accept project-supplied context: skills, AGENTS.md/CLAUDE.md and MCP servers (ADR 9).
    #[serde(default, alias = "allow_skills")]
    pub allow_context: bool,
    /// Also accept MCP servers that run a command inside the sandbox container.
    #[serde(default)]
    pub allow_stdio_mcp: bool,
    /// Hosts whose remote MCP servers tasks may use (the host connects to them, so each is an
    /// explicit opt-in); empty allows none.
    #[serde(default)]
    pub allowed_mcp_hosts: Vec<String>,
    #[serde(default = "default_context_bytes")]
    pub max_context_bytes: u64,
    /// Largest input bundle this runner will unpack into a task workspace.
    #[serde(default = "default_input_bytes")]
    pub max_input_bytes: u64,
}

fn default_input_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_context_bytes() -> u64 {
    64 * 1024
}

fn default_margin() -> u64 {
    25
}

impl Policy {
    pub fn in_quiet_hours(&self, now: DateTime<Local>) -> bool {
        match self.quiet_hours {
            None => false,
            Some((s, e)) => {
                let h = now.hour();
                if s <= e { (s..e).contains(&h) } else { h >= s || h < e }
            }
        }
    }

    /// Checks a verified manifest against consent. `used_today` is total tokens used today.
    pub fn admit(&self, m: &TaskManifest, used_today: u64, now: DateTime<Local>) -> Result<()> {
        let deny = |s: String| Err(Error::Policy(s));
        if self.in_quiet_hours(now) {
            return deny("quiet hours".into());
        }
        if !self.project_shares.contains_key(&m.project_id) {
            return deny(format!("project `{}` not allowed", m.project_id));
        }
        if !self.allowed_kinds.contains(&m.kind) {
            return deny(format!("task kind `{}` not allowed", m.kind));
        }
        if !m.tool_requirements.iter().any(|t| self.available_tools.contains(t)) {
            return deny("no available tool satisfies the task".into());
        }
        if used_today.saturating_add(m.cost_estimate) > self.daily_token_cap {
            return deny("would exceed daily cap".into());
        }
        let (p, max) = (&m.sandbox_profile, &self.max_profile);
        if let Some(h) = p.network_allowlist.iter().find(|h| !max.network_allowlist.contains(h)) {
            return deny(format!("network host `{h}` outside policy"));
        }
        if p.cpu_millis > max.cpu_millis || p.memory_mb > max.memory_mb || p.timeout_secs > max.timeout_secs {
            return deny("sandbox profile exceeds policy limits".into());
        }
        Ok(())
    }

    /// Checks a parsed project context against what this contributor allows (deny by default).
    pub fn admit_context(&self, c: &ProjectContext) -> Result<()> {
        if c.is_empty() {
            return Ok(());
        }
        if !self.allow_context {
            return Err(Error::Policy("project context (skills, instructions, MCP servers) is not allowed".into()));
        }
        if c.bytes() > self.max_context_bytes {
            return Err(Error::Policy(format!("context is {} bytes, limit {}", c.bytes(), self.max_context_bytes)));
        }
        if c.has_stdio_mcp() && !self.allow_stdio_mcp {
            return Err(Error::Policy("MCP servers that run commands inside the sandbox are not allowed".into()));
        }
        for m in &c.mcp {
            if let Some(host) = m.remote_host() {
                if !self.allowed_mcp_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
                    return Err(Error::Policy(format!("mcp host `{host}` not allowed")));
                }
            }
        }
        Ok(())
    }

    /// Picks the candidate whose project is furthest below its resource share.
    pub fn choose<'a>(&self, candidates: &'a [TaskManifest], per_project: &HashMap<String, u64>) -> Option<&'a TaskManifest> {
        let ratio = |m: &TaskManifest| {
            let used = *per_project.get(&m.project_id).unwrap_or(&0) as f64;
            used / self.project_shares[&m.project_id].max(1) as f64
        };
        candidates
            .iter()
            .filter(|m| self.project_shares.contains_key(&m.project_id))
            .min_by(|a, b| ratio(a).total_cmp(&ratio(b)))
    }
}
