//! Task manifests and the manifest verifier (ADR 3: projects sign, runners verify).

use crate::{Error, Result};
use crate::dsse::Envelope;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProfile {
    /// Hosts the task may reach. Empty means default-deny egress.
    #[serde(default)]
    pub network_allowlist: Vec<String>,
    pub cpu_millis: u32,
    pub memory_mb: u32,
    pub timeout_secs: u64,
}

impl Default for SandboxProfile {
    /// The strictest profile: no network, one CPU, 1 GiB, 10 minutes.
    fn default() -> Self {
        Self { network_allowlist: vec![], cpu_millis: 1000, memory_mb: 1024, timeout_secs: 600 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputSchema {
    /// `text` or `json`.
    pub format: String,
    pub max_bytes: usize,
    /// Most bytes of changed files the task may return as artifacts; 0 means none are collected.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_artifact_bytes: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// MCP server name the runner reserves for its own exec bridge; projects cannot use it.
pub const BRIDGE_SERVER_NAME: &str = "sandbox";

/// A project-supplied skill: instructions plus optional reference files (ADR 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skill {
    /// Lowercase kebab-case identifier.
    pub name: String,
    pub description: String,
    /// Markdown body of `SKILL.md`.
    pub content: String,
    /// Extra text files, by relative path.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

/// A remote MCP server. Deliberately just a name and an `https` URL: there is no way to express
/// a command, headers or environment, so stdio servers and credential forwarding are impossible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServer {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskContext {
    #[serde(default)]
    pub skills: Vec<Skill>,
    #[serde(default)]
    pub mcp_servers: Vec<McpServer>,
}

fn ident(s: &str, extra: &[char]) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || extra.contains(&c))
}

fn safe_path(p: &str) -> bool {
    let parts: Vec<&str> = p.split('/').collect();
    parts.len() <= 4
        && p.len() <= 128
        && parts.iter().all(|c| !c.is_empty() && *c != "." && *c != ".." && !c.starts_with('.') && c.chars().all(|ch| ch.is_ascii_alphanumeric() || "._-".contains(ch)))
        && !p.eq_ignore_ascii_case("SKILL.md")
}

impl McpServer {
    /// Host of the URL after checking it is a plain `https` URL.
    pub fn host(&self) -> Result<&str> {
        let bad = |why: &str| Err(Error::Verify(format!("mcp server `{}`: {why}", self.name)));
        let Some(rest) = self.url.strip_prefix("https://") else { return bad("url must start with https://") };
        if self.url.len() > 512 || self.url.chars().any(|c| c.is_whitespace() || c.is_control() || c == '$' || c == '\\') {
            return bad("url contains forbidden characters");
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() || authority.contains('@') {
            return bad("url must have a host and no userinfo");
        }
        Ok(authority.rsplit_once(':').map_or(authority, |(h, port)| if port.chars().all(|c| c.is_ascii_digit()) { h } else { authority }))
    }
}

impl TaskContext {
    pub fn is_empty(&self) -> bool {
        self.skills.is_empty() && self.mcp_servers.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.skills.iter().map(|s| s.name.len() + s.description.len() + s.content.len() + s.files.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()).sum::<usize>()
            + self.mcp_servers.iter().map(|m| m.name.len() + m.url.len()).sum::<usize>()
    }

    /// Structural checks that do not depend on contributor policy.
    pub fn validate(&self) -> Result<()> {
        let bad = |s: String| Err(Error::Verify(s));
        let mut seen = std::collections::HashSet::new();
        for sk in &self.skills {
            if !ident(&sk.name, &[]) || !seen.insert(format!("s:{}", sk.name)) {
                return bad(format!("invalid or duplicate skill name `{}`", sk.name));
            }
            if sk.description.len() > 1024 || sk.description.chars().any(char::is_control) {
                return bad(format!("skill `{}`: description too long or has control characters", sk.name));
            }
            if let Some(p) = sk.files.keys().find(|p| !safe_path(p)) {
                return bad(format!("skill `{}`: unsafe file path `{p}`", sk.name));
            }
        }
        for m in &self.mcp_servers {
            if m.name == BRIDGE_SERVER_NAME || !ident(&m.name, &['_']) || !seen.insert(format!("m:{}", m.name)) {
                return bad(format!("invalid or duplicate mcp server name `{}`", m.name));
            }
            m.host()?;
        }
        Ok(())
    }

    /// For the audit log, e.g. `skills=a,b mcp=host1`.
    pub fn summary(&self) -> String {
        let hosts: Vec<&str> = self.mcp_servers.iter().filter_map(|m| m.host().ok()).collect();
        format!("skills={} mcp={}", self.skills.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(","), hosts.join(","))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskManifest {
    pub id: String,
    pub project_id: String,
    pub kind: String,
    /// Content address (hex SHA-256) of the input bundle.
    pub inputs: String,
    /// The prompt handed to the harness. Untrusted content.
    pub prompt: String,
    pub tool_requirements: Vec<String>,
    pub sandbox_profile: SandboxProfile,
    /// Expected tokens; checked against caps before and during the run.
    pub cost_estimate: u64,
    pub output_schema: OutputSchema,
    pub redundancy: u32,
    /// Optional skills and MCP servers (ADR 9). Omitted from the signed bytes when empty, so
    /// manifests signed before this field existed still verify.
    #[serde(default, skip_serializing_if = "TaskContext::is_empty")]
    pub context: TaskContext,
}

/// DSSE payload type of a signed task manifest.
pub const TASK_PAYLOAD_TYPE: &str = "application/vnd.togra.task+json";

impl TaskManifest {
    /// Signs the manifest as a DSSE envelope. The signed bytes are exactly the JSON payload.
    pub fn sign(&self, key: &SigningKey) -> Result<Envelope> {
        Ok(crate::dsse::sign(TASK_PAYLOAD_TYPE, &serde_json::to_vec(self)?, key))
    }
}

/// The manifest inside an envelope, **unverified** (to find the task id and project). Never act
/// on the result without `TrustedProjects::verify`.
pub fn peek_manifest(env: &Envelope) -> Result<TaskManifest> {
    Ok(serde_json::from_slice(&env.payload_bytes()?)?)
}

/// Project public keys the contributor trusts, keyed by project id.
#[derive(Debug, Clone, Default)]
pub struct TrustedProjects(BTreeMap<String, VerifyingKey>);

impl TrustedProjects {
    pub fn insert(&mut self, project_id: impl Into<String>, key: VerifyingKey) {
        self.0.insert(project_id.into(), key);
    }

    /// Verifies an envelope against the key of the project it claims to be from, and returns
    /// the manifest decoded from the *verified* bytes. Rejects unknown projects, tampered
    /// payloads and wrong payload types.
    pub fn verify(&self, env: &Envelope) -> Result<TaskManifest> {
        let claimed = peek_manifest(env)?;
        let key = self.0.get(&claimed.project_id).ok_or_else(|| Error::Verify(format!("unknown project `{}`", claimed.project_id)))?;
        let payload = env.verify(TASK_PAYLOAD_TYPE, key)?;
        Ok(serde_json::from_slice(&payload)?)
    }
}

/// Generates a fresh ed25519 key from OS randomness.
pub fn generate_key() -> SigningKey {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}
