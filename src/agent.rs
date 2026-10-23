//! The project's Omnigent agent directory: what toto shows a contributor at approval and runs,
//! unchanged, in the project's environment.
//!
//! An agent directory is Omnigent's own format (`config.yaml`, `skills/<name>/...`), committed in
//! the project repository (default `.toto/agent`). toto never generates or edits it: MCP servers,
//! skills, prompt, model and egress rules are all the project's, in Omnigent's syntax. toto only
//! reads it to tell the contributor what they are approving, checks the few things it must know
//! (which harness, so the right credential is used; whether tasks need a network; whether the
//! nested sandbox is used), and carries the approved files into the container at task time.
//!
//! **Instructions** are resolved the way Omnigent resolves them (`omnigent/spec/parser.py`,
//! `_resolve_instructions`), so the contributor sees the prompt that will actually run:
//! `instructions` (or its legacy alias `prompt`) is read as a file when it is one line naming a
//! file inside the agent directory, and as inline text otherwise; with neither set, the first of
//! `AGENTS.md`, `CLAUDE.md`, `.cursorrules` in the agent directory. Omnigent never reads outside the
//! directory, and silently runs the reference itself as the prompt instead, so toto:
//! - refuses a reference to a file that is not there;
//! - for a reference that leaves the agent directory (`instructions: ../../AGENTS.md`, the
//!   repository's own AGENTS.md), ships that one file with the agent, approved and hashed with it,
//!   under `.toto-repo/` (`outside_path`), and points the reference there at task time (`for_run`).

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

/// Where a file the agent's `instructions` reference from outside the agent directory is carried
/// inside it. Reserved: an agent directory may not contain it itself.
pub const OUTSIDE_DIR: &str = ".toto-repo";

/// Files Omnigent reads as instructions when `instructions` and `prompt` are both unset, in order.
pub const CONTEXT_FILES: [&str; 3] = ["AGENTS.md", "CLAUDE.md", ".cursorrules"];

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
    /// Where the prompt comes from: `inline`, or the file (e.g. `AGENTS.md`, or
    /// `../../AGENTS.md` for one shipped from outside the agent directory). `None`: no instructions.
    #[serde(default)]
    pub instructions_from: Option<String>,
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
            format!("prompt      {}{}", self.instructions_from.as_deref().filter(|f| *f != "inline").map_or(String::new(), |f| format!("from {f}: ")), if self.prompt_preview.is_empty() { "(none)" } else { &self.prompt_preview }),
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
            if !self.needs_network {
                "none (tasks run offline)".to_string()
            } else if self.egress_rules.is_empty() {
                "wanted, but no egress rules: OpenShell only grants listed destinations, so tasks are refused".into()
            } else {
                format!("only these requests, each checked by the sandbox: {}", self.egress_rules.join(", "))
            }
        ));
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
    let shipped: Vec<&String> = files.keys().filter(|p| p.starts_with(&format!("{OUTSIDE_DIR}/"))).collect();
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
    let (instructions_from, text) = resolve_instructions(files, &v).map_err(bad)?;
    let prompt_preview = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).or_else(|| text.lines().map(str::trim).find(|l| !l.is_empty())).unwrap_or("").chars().take(120).collect();
    if let Some(p) = shipped.iter().find(|p| instruction_ref(&v).and_then(|r| outside_path(&r)).as_deref() != Some(p.as_str())) {
        return Err(bad(format!("`{p}`: `{OUTSIDE_DIR}/` is reserved for the instructions file toto carries in from outside the agent directory")));
    }

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
        warnings.push("egress_rules are enforced by toto's sandbox (OpenShell); on the deprecated docker sandbox only with os_env.sandbox.type linux_bwrap".into());
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
        warnings.push("an MCP server is reached by URL: tasks need a network for it, and its host must be in the egress rules".into());
    }
    Ok(AgentSummary { harness, model, prompt_preview, instructions_from, mcp, skills, sandbox_type, egress_rules, needs_network, warnings })
}

/// The one-line `instructions` (or, without it, `prompt`) value that Omnigent would try as a file.
pub fn instruction_ref(config: &serde_json::Value) -> Option<String> {
    let raw = if config["instructions"].is_null() { &config["prompt"] } else { &config["instructions"] };
    raw.as_str().filter(|s| !s.contains('\n')).map(|s| s.trim().to_string())
}

/// Where a reference that leaves the agent directory (`../../AGENTS.md`) is carried inside it:
/// `.toto-repo/up/up/AGENTS.md`. `None` for a reference that stays inside, and for one toto does
/// not carry (an absolute path, `..` after a name, `.` segments).
pub fn outside_path(reference: &str) -> Option<String> {
    let segments: Vec<&str> = reference.split('/').collect();
    let ups = segments.iter().take_while(|s| **s == "..").count();
    let rest = &segments[ups..];
    (ups > 0 && !rest.is_empty() && rest.iter().all(|s| !s.is_empty() && *s != "." && *s != "..")).then(|| format!("{OUTSIDE_DIR}/{}{}", "up/".repeat(ups), rest.join("/")))
}

/// Resolves the agent's instructions as Omnigent will (see the module docs): where they come from
/// (`inline`, or a file) and their text. Refuses a reference to a file that is not there, which
/// Omnigent would otherwise run as the prompt text itself.
fn resolve_instructions(files: &BTreeMap<String, Vec<u8>>, config: &serde_json::Value) -> std::result::Result<(Option<String>, String), String> {
    let utf8 = |p: &str, b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| format!("instructions file `{p}` is not UTF-8"));
    let raw = if config["instructions"].is_null() { &config["prompt"] } else { &config["instructions"] };
    if raw.is_null() {
        return Ok(match CONTEXT_FILES.iter().find_map(|f| files.get(*f).map(|b| (*f, b))) {
            Some((f, b)) => (Some(f.to_string()), utf8(f, b)?),
            None => (None, String::new()),
        });
    }
    let text = raw.as_str().ok_or("`instructions`/`prompt` must be text")?.to_string();
    let Some(r) = instruction_ref(config) else { return Ok((Some("inline".into()), text)) };
    let inside = r.strip_prefix("./").unwrap_or(&r);
    if let Some(b) = files.get(inside).filter(|_| archive::valid_path(inside)) {
        return Ok((Some(inside.to_string()), utf8(inside, b)?));
    }
    if let Some(b) = outside_path(&r).and_then(|p| files.get(&p)) {
        return Ok((Some(r.clone()), utf8(&r, b)?));
    }
    let looks_like_a_file = !r.contains(char::is_whitespace) && (r.contains('/') || [".md", ".txt", ".markdown", ".cursorrules"].iter().any(|e| r.to_lowercase().ends_with(e)));
    if looks_like_a_file {
        return Err(format!("instructions `{r}` names a file that is not in the agent directory (Omnigent would run the text `{r}` itself as the prompt)"));
    }
    Ok((Some("inline".into()), text))
}

/// The text of the instructions file `from` (an `instructions_from` other than `inline`).
pub fn instructions_file<'a>(files: &'a BTreeMap<String, Vec<u8>>, from: &str) -> Option<&'a [u8]> {
    files.get(from).or_else(|| files.get(&outside_path(from)?)).map(Vec::as_slice)
}

/// The approved agent directory as the sandbox runs it. Two adjustments, both derived from the
/// approved files alone, and nothing else changed:
/// - an `instructions` reference to a file outside the agent directory points at the copy
///   carried in `.toto-repo/` (Omnigent reads only inside the directory);
/// - with `external_egress` (OpenShell), Omnigent's own network sandbox is turned off
///   (`with_external_egress`).
pub fn for_run(tar: &[u8], external_egress: bool) -> Result<Vec<u8>> {
    let tar = if external_egress { with_external_egress(tar)? } else { tar.to_vec() };
    let mut records = archive::from_bytes(&tar, archive::Limits::new(MAX_BYTES)).map_err(Error::Policy)?;
    let Some(archive::Record::File { data, .. }) = records.iter_mut().find(|r| matches!(r, archive::Record::File { path, .. } if path == "config.yaml" || path == "config.yml")) else {
        return Ok(tar);
    };
    let mut v: serde_yaml_ng::Value = serde_yaml_ng::from_slice(data).map_err(|e| Error::Policy(format!("agent config.yaml: {e}")))?;
    let key = if v.get("instructions").is_some_and(|i| !i.is_null()) { "instructions" } else { "prompt" };
    let Some(target) = v.get(key).and_then(serde_yaml_ng::Value::as_str).filter(|s| !s.contains('\n')).and_then(|r| outside_path(r.trim())) else { return Ok(tar) };
    v[key] = target.into();
    *data = serde_yaml_ng::to_string(&v).map_err(|e| Error::Policy(e.to_string()))?.into_bytes();
    archive::to_bytes(&records).map_err(Error::Policy)
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

/// The approved agent directory as a sandbox that enforces the egress rules itself runs it
/// (OpenShell): Omnigent's own network sandbox (`os_env.sandbox`) is replaced by `{type: none}`
/// (with `allow_network: true` for a networked agent), because a nested bubblewrap cannot start there and the very
/// same rules are enforced from outside the workload instead. Everything else stays byte for byte
/// as approved. Returns the tar unchanged when the agent has no `os_env.sandbox`.
pub fn with_external_egress(tar: &[u8]) -> Result<Vec<u8>> {
    let mut records = archive::from_bytes(tar, archive::Limits::new(MAX_BYTES)).map_err(Error::Policy)?;
    let Some(archive::Record::File { data, .. }) = records.iter_mut().find(|r| matches!(r, archive::Record::File { path, .. } if path == "config.yaml")) else {
        return Err(Error::Policy("agent directory: no config.yaml".into()));
    };
    let mut v: serde_yaml_ng::Value = serde_yaml_ng::from_slice(data).map_err(|e| Error::Policy(format!("agent config.yaml: {e}")))?;
    let Some(sandbox) = v.get_mut("os_env").and_then(|o| o.get_mut("sandbox")) else { return Ok(tar.to_vec()) };
    let allow = sandbox.get("allow_network").and_then(serde_yaml_ng::Value::as_bool).unwrap_or(false);
    let mut replaced = serde_yaml_ng::Mapping::new();
    replaced.insert("type".into(), "none".into());
    if allow {
        // Omnigent rejects `allow_network: false` with `type: none` ("cannot restrict network").
        replaced.insert("allow_network".into(), true.into());
    }
    *sandbox = serde_yaml_ng::Value::Mapping(replaced);
    *data = serde_yaml_ng::to_string(&v).map_err(|e| Error::Policy(e.to_string()))?.into_bytes();
    archive::to_bytes(&records).map_err(Error::Policy)
}
