//! The project's Omnigent agent directory: what toto shows a contributor at approval and runs,
//! unchanged, in the project's environment.
//!
//! An agent directory is Omnigent's own format (`config.yaml`, `skills/<name>/...`), committed in
//! the project repository (default `.toto/agent`). toto never generates or edits it: MCP servers,
//! skills, prompt, model and egress rules are all the project's, in Omnigent's syntax. toto only
//! reads it to tell the contributor what they are approving, checks the few things it must know
//! (which harness, so the right credential is used; whether tasks need a network; whether the
//! nested sandbox is used), and carries the approved files into the container at task time.

use crate::archive::{self, Record};
use crate::proxy::Provider;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Where the agent directory lives in the project repository unless `customizations.toto.agent`
/// says otherwise.
pub const DEFAULT_AGENT_DIR: &str = ".toto/agent";
/// Where the approved agent directory is unpacked inside the container (a writable tmpfs).
pub const CONTAINER_AGENT_DIR: &str = "/tmp/toto-agent";

pub const MAX_FILES: usize = 500;
pub const MAX_BYTES: u64 = 1 << 20;

/// What a contributor sees and approves. Stored with the approval, so `list` and `doctor` can
/// show it without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSummary {
    /// Omnigent harness, e.g. `claude-sdk` or `codex`.
    pub harness: String,
    pub model: Option<String>,
    /// First line of the agent's prompt, for the listing.
    pub prompt_preview: String,
    /// MCP servers: name and `command ...` or `url`.
    pub mcp: Vec<(String, String)>,
    pub skills: Vec<String>,
    /// `os_env.sandbox.type` when set (`linux_bwrap` needs the contributor's nested-userns profile).
    pub sandbox_type: Option<String>,
    pub egress_rules: Vec<String>,
    /// Tasks need a network: the sandbox allows it, or an MCP server is reached by URL.
    pub needs_network: bool,
    pub warnings: Vec<String>,
}

impl AgentSummary {
    pub fn needs_nested_sandbox(&self) -> bool {
        self.sandbox_type.as_deref() == Some("linux_bwrap")
    }

    /// The credential this agent's harness uses.
    pub fn provider(&self) -> Option<Provider> {
        provider_for(&self.harness)
    }

    pub fn describe(&self) -> Vec<String> {
        let mut out = vec![
            format!("harness     {}{}", self.harness, self.model.as_deref().map_or(String::new(), |m| format!(", model {m}"))),
            format!("credential  {}", match self.provider() { Some(Provider::Anthropic) => "Anthropic (Claude subscription or API key)", Some(Provider::OpenAi) => "OpenAI API key", None => "unknown harness: no credential of yours matches" }),
            format!("prompt      {}", self.prompt_preview),
            format!("skills      {}", if self.skills.is_empty() { "none".into() } else { self.skills.join(", ") }),
        ];
        if self.mcp.is_empty() {
            out.push("mcp         none".into());
        }
        for (name, what) in &self.mcp {
            out.push(format!("mcp         {name}: {what}"));
        }
        out.push(format!(
            "network     {}",
            if !self.needs_network { "none (tasks run offline)".to_string() } else if self.egress_rules.is_empty() { "allowed, no egress rules (any destination the fenced network reaches)".into() } else { format!("rules: {}", self.egress_rules.join(", ")) }
        ));
        if let Some(t) = &self.sandbox_type {
            out.push(format!("sandbox     Omnigent `{t}` inside the container{}", if self.needs_nested_sandbox() { " (needs `nested_userns` in your sandbox config)" } else { "" }));
        }
        out.extend(self.warnings.iter().map(|w| format!("note        {w}")));
        out
    }
}

/// Which credential a harness uses. Unknown harnesses are refused at approval.
pub fn provider_for(harness: &str) -> Option<Provider> {
    match harness {
        "claude-sdk" | "claude" => Some(Provider::Anthropic),
        "codex" | "openai-agents" | "open-responses" => Some(Provider::OpenAi),
        _ => None,
    }
}

/// Whether `rule` is a well-formed Omnigent egress rule: `METHODS host/path`.
pub fn valid_egress_rule(rule: &str) -> bool {
    let Some((methods, target)) = rule.split_once(' ') else { return false };
    let methods_ok = methods == "*" || methods.split(',').all(|m| !m.is_empty() && m.bytes().all(|b| b.is_ascii_uppercase()));
    let Some((host, path)) = target.split_once('/') else { return false };
    let host = host.strip_prefix("*.").unwrap_or(host);
    methods_ok && !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') && !path.contains(char::is_whitespace)
}

fn ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Reads the agent directory (paths relative to it) and says what it does. Refuses what toto
/// cannot run: no `config.yaml`, an unknown harness, an `os_env` that is not the container itself.
pub fn summarize(files: &BTreeMap<String, Vec<u8>>) -> Result<AgentSummary> {
    let bad = |m: String| Error::Policy(format!("agent directory: {m}"));
    if files.len() > MAX_FILES {
        return Err(bad(format!("more than {MAX_FILES} files")));
    }
    let total: u64 = files.values().map(|v| v.len() as u64).sum();
    if total > MAX_BYTES {
        return Err(bad(format!("{total} bytes, limit {MAX_BYTES}")));
    }
    if let Some(p) = files.keys().find(|p| !archive::valid_path(p)) {
        return Err(bad(format!("unsafe path `{p}`")));
    }
    let config = files.get("config.yaml").or_else(|| files.get("config.yml")).ok_or_else(|| bad("no config.yaml".into()))?;
    let text = std::str::from_utf8(config).map_err(|_| bad("config.yaml is not UTF-8".into()))?;
    let v: serde_json::Value = serde_yaml_ng::from_str(text).map_err(|e| bad(format!("config.yaml: {e}")))?;
    let mut warnings = vec![];

    let harness = v["executor"]["config"]["harness"].as_str().ok_or_else(|| bad("config.yaml must set executor.config.harness (toto needs to know which credential the agent uses)".into()))?.to_string();
    if provider_for(&harness).is_none() {
        return Err(bad(format!("harness `{harness}` is not one toto can supply a credential for (claude-sdk, codex, openai-agents, open-responses)")));
    }
    let model = v["executor"]["model"].as_str().map(String::from);
    if model.is_none() {
        warnings.push("no executor.model: Omnigent cannot discover models through the credential proxy, so tasks may fail to start".into());
    }
    let prompt_preview = v["prompt"].as_str().unwrap_or("").lines().next().unwrap_or("").chars().take(120).collect();

    match v["os_env"]["type"].as_str() {
        None | Some("caller_process") => {}
        Some(other) => return Err(bad(format!("os_env.type `{other}` is not supported: the container is the environment (use caller_process or leave os_env out)"))),
    }
    let sandbox = &v["os_env"]["sandbox"];
    let sandbox_type = sandbox["type"].as_str().filter(|t| *t != "none").map(String::from);
    let egress_rules: Vec<String> = sandbox["egress_rules"].as_array().into_iter().flatten().filter_map(|r| r.as_str().map(String::from)).collect();
    if let Some(r) = egress_rules.iter().find(|r| !valid_egress_rule(r)) {
        return Err(bad(format!("malformed egress rule `{r}` (expected `METHODS host/path`, e.g. `GET api.github.com/repos/org/**`)")));
    }
    let allow_network = sandbox["allow_network"].as_bool().unwrap_or(false);
    if !egress_rules.is_empty() && !allow_network {
        warnings.push("egress_rules are set but allow_network is false: Omnigent will refuse all network".into());
    }
    if !egress_rules.is_empty() && sandbox_type.as_deref() != Some("linux_bwrap") {
        warnings.push("egress_rules only apply with os_env.sandbox.type linux_bwrap".into());
    }

    let mut mcp = vec![];
    let mut url_servers = false;
    if let Some(tools) = v["tools"].as_object() {
        for (name, t) in tools {
            if t["type"].as_str() != Some("mcp") {
                continue;
            }
            if let Some(url) = t["url"].as_str() {
                url_servers = true;
                mcp.push((name.clone(), url.to_string()));
            } else if let Some(cmd) = t["command"].as_str() {
                let args: Vec<&str> = t["args"].as_array().into_iter().flatten().filter_map(|a| a.as_str()).collect();
                mcp.push((name.clone(), format!("{cmd} {}", args.join(" ")).trim().to_string()));
            }
        }
    }
    if v["tools"]["sandbox"]["container_image"].is_string() {
        warnings.push("tools.sandbox.container_image needs a docker daemon, which tasks do not have".into());
    }
    let mut skills: Vec<String> = files.keys().filter_map(|p| p.strip_prefix("skills/")).filter_map(|rest| rest.split('/').next()).map(String::from).collect();
    skills.sort();
    skills.dedup();
    if let Some(s) = skills.iter().find(|s| !ident(s)) {
        return Err(bad(format!("skill directory `{s}` is not a simple lowercase name")));
    }
    let needs_network = allow_network || url_servers;
    if url_servers && !allow_network {
        warnings.push("an MCP server is reached by URL: tasks get the fenced network for it".into());
    }
    Ok(AgentSummary { harness, model, prompt_preview, mcp, skills, sandbox_type, egress_rules, needs_network, warnings })
}

/// The agent directory as a tar (what the approval stores and the container receives).
pub fn pack(files: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let records: Vec<Record> = files.iter().map(|(p, d)| Record::File { path: p.clone(), mode: 0o644, data: d.clone() }).collect();
    archive::to_bytes(&records).map_err(Error::Policy)
}

/// Back from the stored tar.
pub fn unpack(tar: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let records = archive::from_bytes(tar, archive::Limits::new(MAX_BYTES)).map_err(Error::Policy)?;
    Ok(records.into_iter().filter_map(|r| match r {
        Record::File { path, data, .. } => Some((path, data)),
        Record::Deleted { .. } => None,
    }).collect())
}

pub fn hash(tar: &[u8]) -> String {
    archive::sha256_hex(tar)
}
