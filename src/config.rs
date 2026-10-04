//! Daemon configuration: everything that decides what runs, where and under which limits.

use crate::audit::AuditLog;
use crate::harness::{EchoHarness, Harness};
use crate::manifest::{generate_key, TrustedProjects};
use crate::claude_cli::ClaudeCliHarness;
use crate::omnigent::OmnigentHarness;
use crate::policy::Policy;
use crate::queue::{DirQueue, QueueClient};
use crate::runner::{Reviewer, Runner};
use crate::sandbox::{BwrapSandbox, DirSandbox, DockerSandbox, Sandbox};
use crate::{Error, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SandboxConfig {
    /// A plain directory. **No isolation**; development only.
    Dir,
    /// Docker or Podman; set `runtime` to `runsc` for gVisor.
    Docker {
        #[serde(default = "docker_bin")]
        bin: String,
        image: String,
        #[serde(default)]
        runtime: Option<String>,
        /// Path to the static `togra-mcp-exec` binary, mounted read-only into the container.
        #[serde(default)]
        bridge: Option<PathBuf>,
    },
    /// bubblewrap (Linux), no daemon or image.
    Bwrap,
}

fn docker_bin() -> String {
    "docker".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum HarnessConfig {
    /// Placeholder until the Omnigent harness lands.
    Echo { tokens_per_run: u64 },
    /// The official `claude` CLI with the contributor's subscription token (ADR 11). Needs a
    /// container sandbox with the exec bridge.
    Claude {
        #[serde(default = "claude_bin")]
        bin: String,
        /// Token from `claude setup-token`, stored by `togra login` (default: <state_dir>/claude.token).
        #[serde(default)]
        token_file: Option<PathBuf>,
        #[serde(default)]
        model: Option<String>,
    },
    /// Omnigent in no-network mode (see `omnigent.rs`); needs sandbox `dir` or `bwrap`.
    Omnigent {
        #[serde(default = "omnigent_bin")]
        bin: String,
        #[serde(default = "omnigent_url")]
        server_url: String,
        #[serde(default = "omnigent_harness")]
        harness: String,
    },
}

fn claude_bin() -> String {
    "claude".into()
}
fn omnigent_bin() -> String {
    "omnigent".into()
}
fn omnigent_url() -> String {
    "http://127.0.0.1:6767".into()
}
fn omnigent_harness() -> String {
    "claude-sdk".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub key_file: PathBuf,
    pub state_dir: PathBuf,
    /// Spool directory acting as the queue (see `DirQueue`).
    pub queue_dir: PathBuf,
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
    pub sandbox: SandboxConfig,
    pub harness: HarnessConfig,
    pub policy: Policy,
    /// Trusted project public keys (hex ed25519), by project id.
    #[serde(default)]
    pub projects: BTreeMap<String, String>,
}

fn default_poll() -> u64 {
    30
}

/// The daemon has no human to ask, so review-before-submit is refused at startup.
struct NoReview;
impl Reviewer for NoReview {
    fn approve(&self, _: &crate::manifest::TaskManifest, _: &crate::result::SignedResult) -> bool {
        false
    }
}

pub type DaemonRunner = Runner<Arc<dyn QueueClient>, Box<dyn Harness>, Box<dyn Sandbox>, Box<dyn Reviewer>>;

impl Reviewer for Box<dyn Reviewer> {
    fn approve(&self, t: &crate::manifest::TaskManifest, r: &crate::result::SignedResult) -> bool {
        (**self).approve(t, r)
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    /// A safe starter config: strict policy and no trusted projects, so nothing runs until the
    /// contributor adds one.
    pub fn starter(dir: &Path) -> Self {
        Config {
            key_file: dir.join("runner.key"),
            state_dir: dir.join("state"),
            queue_dir: dir.join("queue"),
            poll_secs: default_poll(),
            sandbox: SandboxConfig::Docker { bin: docker_bin(), image: "alpine".into(), runtime: None, bridge: None },
            harness: HarnessConfig::Echo { tokens_per_run: 100 },
            policy: Policy {
                daily_token_cap: 100_000,
                project_shares: BTreeMap::new(),
                allowed_kinds: vec![],
                quiet_hours: None,
                review_before_submit: false,
                max_profile: Default::default(),
                abort_margin_pct: 25,
                available_tools: vec!["echo".into()],
                allow_skills: false,
                allowed_mcp_hosts: vec![],
                max_context_bytes: 64 * 1024,
                max_input_bytes: 64 * 1024 * 1024,
            },
            projects: BTreeMap::new(),
        }
    }

    /// Loads the runner key, creating it (mode 0600) on first use.
    pub fn load_or_create_key(&self) -> Result<SigningKey> {
        use std::os::unix::fs::PermissionsExt;
        if !self.key_file.exists() {
            let k = generate_key();
            std::fs::write(&self.key_file, hex::encode(k.to_bytes()))?;
            std::fs::set_permissions(&self.key_file, std::fs::Permissions::from_mode(0o600))?;
        }
        let seed: [u8; 32] = hex::decode(std::fs::read_to_string(&self.key_file)?.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::Policy("runner key file is not a 32-byte hex seed".into()))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    /// Default location of the subscription token.
    pub fn token_path(&self) -> PathBuf {
        self.state_dir.join("claude.token")
    }

    pub fn build_sandbox(&self) -> Box<dyn Sandbox> {
        let work = self.state_dir.join("work");
        match &self.sandbox {
            SandboxConfig::Dir => Box::new(DirSandbox { root: work }),
            SandboxConfig::Bwrap => Box::new(BwrapSandbox::new(work)),
            SandboxConfig::Docker { bin, image, runtime, bridge } => {
                let mut s = DockerSandbox::new(image);
                s.bin = bin.clone();
                s.runtime = runtime.clone();
                s.bridge = bridge.clone();
                Box::new(s)
            }
        }
    }

    pub fn build(&self) -> Result<DaemonRunner> {
        if self.policy.review_before_submit {
            return Err(Error::Policy("review_before_submit needs the TUI; the daemon cannot ask a human".into()));
        }
        std::fs::create_dir_all(&self.state_dir)?;
        let mut trusted = TrustedProjects::default();
        for (id, k) in &self.projects {
            let bytes: [u8; 32] = hex::decode(k).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| Error::Verify(format!("bad key for project `{id}`")))?;
            trusted.insert(id, VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Verify(format!("bad key for project `{id}`")))?);
        }
        let harness: Box<dyn Harness> = match &self.harness {
            HarnessConfig::Echo { tokens_per_run } => Box::new(EchoHarness { tokens_per_run: *tokens_per_run }),
            HarnessConfig::Claude { bin, token_file, model } => {
                if !matches!(self.sandbox, SandboxConfig::Docker { bridge: Some(_), .. }) {
                    return Err(Error::Policy("the claude harness needs a Docker/Podman sandbox with `bridge` set to the static togra-mcp-exec binary".into()));
                }
                let mut h = ClaudeCliHarness::new(&self.state_dir, token_file.clone().unwrap_or_else(|| self.token_path()))?;
                h.bin = bin.clone();
                h.model = model.clone();
                Box::new(h)
            }
            HarnessConfig::Omnigent { bin, server_url, harness } => {
                if matches!(self.sandbox, SandboxConfig::Docker { bridge: None, .. }) {
                    return Err(Error::Policy("the omnigent harness with a container sandbox needs the exec bridge: set `bridge` to the static togra-mcp-exec binary (or use sandbox `dir` or `bwrap`)".into()));
                }
                let mut h = OmnigentHarness::new(&self.state_dir)?;
                h.bin = bin.clone();
                h.server_url = server_url.clone();
                h.harness = harness.clone();
                Box::new(h)
            }
        };
        let queue: Arc<dyn QueueClient> = Arc::new(DirQueue::new(&self.queue_dir)?);
        Ok(Runner::new(
            self.policy.clone(),
            trusted,
            self.load_or_create_key()?,
            queue,
            harness,
            self.build_sandbox(),
            Box::new(NoReview),
            AuditLog::new(self.state_dir.join("audit.jsonl")),
        ))
    }
}
