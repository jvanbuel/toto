//! Daemon configuration: everything that decides what runs, where and under which limits.

use crate::audit::AuditLog;
use crate::harness::{EchoHarness, Harness};
use crate::manifest::{generate_key, TrustedProjects};
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
    fn approve(&self, _: &crate::manifest::TaskManifest, _: &crate::result::TaskResult) -> bool {
        false
    }
}

pub type DaemonRunner = Runner<Arc<dyn QueueClient>, Box<dyn Harness>, Box<dyn Sandbox>, Box<dyn Reviewer>>;

impl Reviewer for Box<dyn Reviewer> {
    fn approve(&self, t: &crate::manifest::TaskManifest, r: &crate::result::TaskResult) -> bool {
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
            sandbox: SandboxConfig::Docker { bin: docker_bin(), image: "alpine".into(), runtime: None },
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

    pub fn build_sandbox(&self) -> Box<dyn Sandbox> {
        let work = self.state_dir.join("work");
        match &self.sandbox {
            SandboxConfig::Dir => Box::new(DirSandbox { root: work }),
            SandboxConfig::Bwrap => Box::new(BwrapSandbox::new(work)),
            SandboxConfig::Docker { bin, image, runtime } => {
                let mut s = DockerSandbox::new(image);
                s.bin = bin.clone();
                s.runtime = runtime.clone();
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
        let HarnessConfig::Echo { tokens_per_run } = self.harness;
        let queue: Arc<dyn QueueClient> = Arc::new(DirQueue::new(&self.queue_dir)?);
        Ok(Runner::new(
            self.policy.clone(),
            trusted,
            self.load_or_create_key()?,
            queue,
            Box::new(EchoHarness { tokens_per_run }),
            self.build_sandbox(),
            Box::new(NoReview),
            AuditLog::new(self.state_dir.join("audit.jsonl")),
        ))
    }
}
