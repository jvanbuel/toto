//! Project context in the formats agents already use (ADR 9, revised):
//!
//! - `.mcp.json`: Claude Code's MCP server config (`{"mcpServers": {...}}`);
//! - `.claude/skills/<name>/SKILL.md` (+ files): [Agent Skills](https://agentskills.io);
//! - `AGENTS.md` / `CLAUDE.md`: agent instructions.
//!
//! A project ships these as a tar laid out like a repository root. Only exactly these paths are
//! accepted: Claude Code hooks, settings, commands and agents (anything under `.claude/` besides
//! `skills/`) can run commands on the host, so they are refused outright. MCP entries are
//! restricted to what is safe to hand over: a command to run *inside the sandbox* (never on the
//! host), or a remote https URL. Headers, OAuth fields, and anything containing `$` (which the
//! CLI would expand from its own environment, including the subscription token) are refused.

use crate::archive::{self, Limits, Record};
use crate::manifest::BRIDGE_SERVER_NAME;
use crate::{Error, Result};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skill {
    pub name: String,
    /// Files relative to the skill directory, including `SKILL.md`.
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpEntry {
    /// Started inside the sandbox container by the runner (`docker exec -i ...`).
    Stdio { name: String, command: String, args: Vec<String>, env: BTreeMap<String, String> },
    /// A remote server the host connects to (needs `allowed_mcp_hosts`).
    Remote { name: String, sse: bool, url: String },
}

impl McpEntry {
    pub fn name(&self) -> &str {
        match self {
            McpEntry::Stdio { name, .. } | McpEntry::Remote { name, .. } => name,
        }
    }

    /// Host of a remote server's URL (`https` only, no userinfo).
    pub fn remote_host(&self) -> Option<&str> {
        let McpEntry::Remote { url, .. } = self else { return None };
        let authority = url.strip_prefix("https://")?.split(['/', '?', '#']).next()?;
        Some(authority.rsplit_once(':').map_or(authority, |(h, port)| if port.chars().all(|c| c.is_ascii_digit()) { h } else { authority }))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectContext {
    pub skills: Vec<Skill>,
    /// `AGENTS.md` and `CLAUDE.md` text, by file name.
    pub instructions: BTreeMap<String, String>,
    pub mcp: Vec<McpEntry>,
    pub(crate) bytes: u64,
}

fn bad<T>(s: impl Into<String>) -> Result<T> {
    Err(Error::Verify(s.into()))
}

fn ident(s: &str, extra: &[char]) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || extra.contains(&c))
}

fn safe_string(s: &str) -> bool {
    s.len() <= 1024 && !s.chars().any(|c| c.is_control() || c == '$')
}

impl ProjectContext {
    pub fn is_empty(&self) -> bool {
        self.skills.is_empty() && self.instructions.is_empty() && self.mcp.is_empty()
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn has_stdio_mcp(&self) -> bool {
        self.mcp.iter().any(|m| matches!(m, McpEntry::Stdio { .. }))
    }

    /// For the audit log, e.g. `skills=a,b mcp=tracker(stdio),docs(docs.example.org)`.
    pub fn summary(&self) -> String {
        let mcp: Vec<String> = self.mcp.iter().map(|m| format!("{}({})", m.name(), m.remote_host().unwrap_or("stdio"))).collect();
        format!("skills={} instructions={} mcp={}", self.skills.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(","), self.instructions.keys().cloned().collect::<Vec<_>>().join(","), mcp.join(","))
    }

    /// Parses and validates a context tar. Everything not on the allow-list is an error.
    pub fn parse(bundle: &[u8], limits: Limits) -> Result<Self> {
        let records = archive::from_bytes(bundle, limits).map_err(Error::Verify)?;
        let mut ctx = ProjectContext::default();
        let mut skill_files: BTreeMap<String, BTreeMap<String, Vec<u8>>> = BTreeMap::new();
        for r in records {
            let Record::File { path, data, .. } = r else { return bad("a context bundle cannot contain deletions") };
            ctx.bytes += data.len() as u64;
            match path.as_str() {
                ".mcp.json" => ctx.mcp = parse_mcp(&data)?,
                "AGENTS.md" | "CLAUDE.md" => {
                    let text = String::from_utf8(data).or_else(|_| bad(format!("{path} is not UTF-8")))?;
                    if text.len() > 32 * 1024 {
                        return bad(format!("{path} is larger than 32 KiB"));
                    }
                    ctx.instructions.insert(path, text);
                }
                p if p.starts_with(".claude/skills/") => {
                    let rest = &p[".claude/skills/".len()..];
                    let Some((name, file)) = rest.split_once('/') else { return bad(format!("`{p}` is not inside a skill directory")) };
                    skill_files.entry(name.to_string()).or_default().insert(file.to_string(), data);
                }
                other => return bad(format!("`{other}` is not allowed in a context bundle (allowed: .mcp.json, AGENTS.md, CLAUDE.md, .claude/skills/<name>/...)")),
            }
        }
        for (name, files) in skill_files {
            if !ident(&name, &[]) {
                return bad(format!("invalid skill name `{name}` (lowercase letters, digits and hyphens)"));
            }
            if files.len() > 200 {
                return bad(format!("skill `{name}` has more than 200 files"));
            }
            let md = files.get("SKILL.md").ok_or_else(|| Error::Verify(format!("skill `{name}` has no SKILL.md")))?;
            check_frontmatter(&name, md)?;
            ctx.skills.push(Skill { name, files });
        }
        Ok(ctx)
    }
}

/// `SKILL.md` must start with YAML frontmatter holding `name` (equal to the directory) and `description`.
fn check_frontmatter(dir: &str, md: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(md).or_else(|_| bad(format!("skill `{dir}`: SKILL.md is not UTF-8")))?;
    let Some(rest) = text.strip_prefix("---\n") else { return bad(format!("skill `{dir}`: SKILL.md must start with `---` frontmatter")) };
    let Some((front, _)) = rest.split_once("\n---") else { return bad(format!("skill `{dir}`: SKILL.md frontmatter is not closed")) };
    let value = |key: &str| front.lines().find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix(':')).map(|v| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string()));
    if value("name").as_deref() != Some(dir) {
        return bad(format!("skill `{dir}`: frontmatter `name` must equal the directory name"));
    }
    match value("description") {
        Some(d) if d.len() <= 1024 => Ok(()),
        Some(_) => bad(format!("skill `{dir}`: description longer than 1024 characters")),
        None => bad(format!("skill `{dir}`: frontmatter needs a `description`")),
    }
}

fn parse_mcp(data: &[u8]) -> Result<Vec<McpEntry>> {
    let v: Value = serde_json::from_slice(data).or_else(|e| bad(format!(".mcp.json: {e}")))?;
    let obj = v.as_object().ok_or_else(|| Error::Verify(".mcp.json must be an object".into()))?;
    if obj.keys().any(|k| k != "mcpServers") {
        return bad(".mcp.json may only contain `mcpServers`");
    }
    let servers = obj.get("mcpServers").and_then(Value::as_object).ok_or_else(|| Error::Verify(".mcp.json needs an `mcpServers` object".into()))?;
    let mut out = Vec::new();
    for (name, s) in servers {
        if name == BRIDGE_SERVER_NAME || !ident(name, &['_']) {
            return bad(format!("invalid or reserved mcp server name `{name}`"));
        }
        let s = s.as_object().ok_or_else(|| Error::Verify(format!("mcp server `{name}` must be an object")))?;
        if let Some(k) = s.keys().find(|k| !["type", "url", "command", "args", "env"].contains(&k.as_str())) {
            return bad(format!("mcp server `{name}`: field `{k}` is not allowed (headers, OAuth and other fields are refused)"));
        }
        let text = |k: &str| -> Result<Option<String>> {
            match s.get(k) {
                None => Ok(None),
                Some(Value::String(x)) if safe_string(x) => Ok(Some(x.clone())),
                Some(_) => bad(format!("mcp server `{name}`: `{k}` must be a plain string without `$` or control characters")),
            }
        };
        match (text("command")?, text("url")?) {
            (Some(command), None) => {
                if s.get("type").is_some_and(|t| t != "stdio") {
                    return bad(format!("mcp server `{name}`: a command server must have type `stdio` or none"));
                }
                let args = match s.get("args") {
                    None => vec![],
                    Some(Value::Array(a)) if a.len() <= 64 && a.iter().all(|x| x.as_str().is_some_and(safe_string)) => a.iter().map(|x| x.as_str().unwrap().to_string()).collect(),
                    Some(_) => return bad(format!("mcp server `{name}`: `args` must be up to 64 plain strings")),
                };
                let env = match s.get("env") {
                    None => BTreeMap::new(),
                    Some(Value::Object(e)) if e.len() <= 32 => e
                        .iter()
                        .map(|(k, v)| match v.as_str() {
                            Some(x) if safe_string(x) && !k.is_empty() && k.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') => Ok((k.clone(), x.to_string())),
                            _ => bad(format!("mcp server `{name}`: bad env entry `{k}`")),
                        })
                        .collect::<Result<_>>()?,
                    Some(_) => return bad(format!("mcp server `{name}`: `env` must be an object of up to 32 plain strings")),
                };
                out.push(McpEntry::Stdio { name: name.clone(), command, args, env });
            }
            (None, Some(url)) => {
                let sse = match s.get("type").and_then(Value::as_str) {
                    Some("http") => false,
                    Some("sse") => true,
                    _ => return bad(format!("mcp server `{name}`: a url server needs type `http` or `sse`")),
                };
                if s.contains_key("args") || s.contains_key("env") {
                    return bad(format!("mcp server `{name}`: `args` and `env` only apply to command servers"));
                }
                let entry = McpEntry::Remote { name: name.clone(), sse, url };
                match entry.remote_host() {
                    Some(h) if !h.is_empty() && !entry_url_has_userinfo(&entry) => out.push(entry),
                    _ => return bad(format!("mcp server `{name}`: url must be https://host/... with no userinfo")),
                }
            }
            _ => return bad(format!("mcp server `{name}`: give exactly one of `command` or `url`")),
        }
    }
    Ok(out)
}

fn entry_url_has_userinfo(e: &McpEntry) -> bool {
    let McpEntry::Remote { url, .. } = e else { return false };
    url.strip_prefix("https://").and_then(|r| r.split(['/', '?', '#']).next()).is_none_or(|a| a.contains('@'))
}
