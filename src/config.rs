//! Daemon configuration: everything that decides what runs, where and under which limits.

use crate::audit::AuditLog;
use crate::harness::{EchoHarness, Harness};
use crate::manifest::{generate_key, TrustedProjects};
use crate::omnigent::{ApprovedAgent, OmnigentHarness};
use crate::policy::Policy;
use crate::projects::Approval;
use crate::proxy::Provider;
use crate::queue::{DirQueue, MultiQueue, QueueClient};
use crate::runner::{Reviewer, Runner};
use crate::sandbox::{DirSandbox, DockerSandbox, Environment, Sandbox};
use crate::{Error, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SandboxConfig {
    /// A plain directory. **No isolation**; development and tests only.
    Dir,
    /// Docker or Podman; set `runtime` to `runsc` for gVisor. Tasks run in each project's approved image.
    Docker {
        #[serde(default = "docker_bin")]
        bin: String,
        #[serde(default)]
        runtime: Option<String>,
        /// Use toto's seccomp profile that allows a nested bubblewrap, so Omnigent can run its own
        /// sandbox inside the container (see `profiles/README.md`). Opt-in.
        #[serde(default)]
        nested_userns: bool,
        /// Fenced docker network for agents that need one (`toto net-setup`).
        #[serde(default)]
        network: Option<String>,
    },
}

fn docker_bin() -> String {
    "docker".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum HarnessConfig {
    /// Echoes the prompt; development and tests only.
    Echo { tokens_per_run: u64 },
    /// Omnigent inside the project's image, behind the credential proxy.
    Omnigent {
        /// Which API the proxy fronts. Projects whose agent uses the other one are refused.
        #[serde(default)]
        provider: ProviderConfig,
        /// API origin the proxy forwards to; default per provider.
        #[serde(default)]
        upstream: Option<String>,
        /// Subscription token file (Anthropic) when no `api_key_file` is given.
        #[serde(default)]
        token_file: Option<PathBuf>,
        /// API key file; required for the `openai` provider.
        #[serde(default)]
        api_key_file: Option<PathBuf>,
    },
}

/// Which model API the credential proxy fronts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderConfig {
    #[default]
    Anthropic,
    Openai,
}

impl ProviderConfig {
    pub fn provider(self) -> Provider {
        match self {
            ProviderConfig::Anthropic => Provider::Anthropic,
            ProviderConfig::Openai => Provider::OpenAi,
        }
    }

    fn default_upstream(self) -> &'static str {
        match self {
            ProviderConfig::Anthropic => "https://api.anthropic.com",
            ProviderConfig::Openai => "https://api.openai.com",
        }
    }
}

/// Docker's default seccomp profile plus what a nested bubblewrap needs (generated; see profiles/).
const NESTED_USERNS_PROFILE: &str = include_str!("../profiles/seccomp-nested-userns.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub key_file: PathBuf,
    pub state_dir: PathBuf,
    /// Spool directory used as the queue when `queues` is empty (development and `post-task`).
    pub queue_dir: PathBuf,
    /// Where tasks come from. With several, tasks from all are considered and each claim goes
    /// back to the queue the task came from.
    #[serde(default)]
    pub queues: Vec<QueueEndpoint>,
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
    pub sandbox: SandboxConfig,
    pub harness: HarnessConfig,
    pub policy: Policy,
    /// Trusted project public keys (hex ed25519), by project id.
    #[serde(default)]
    pub projects: BTreeMap<String, String>,
    /// Each project's approved environment and agent (`toto projects add`), by project id.
    #[serde(default)]
    pub environments: BTreeMap<String, Approval>,
    /// Where each project was added from (`owner/name` on GitHub), set by `toto projects add`.
    #[serde(default)]
    pub sources: BTreeMap<String, String>,
    /// The signed project directory `toto projects add <name>` resolves names through.
    #[serde(default)]
    pub directory: DirectoryConfig,
}

/// Where the signed project directory is and whose key signs it (`crate::directory`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryConfig {
    /// `owner/name` of the repository holding the directory file.
    #[serde(default = "directory_repo")]
    pub repo: String,
    #[serde(default = "directory_path")]
    pub path: String,
    /// Hex Ed25519 public key of the directory maintainers.
    #[serde(default = "directory_key")]
    pub public_key: String,
    #[serde(default = "github_api")]
    pub api_url: String,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self { repo: directory_repo(), path: directory_path(), public_key: directory_key(), api_url: github_api() }
    }
}

fn directory_repo() -> String {
    crate::directory::DEFAULT_REPO.into()
}
fn directory_path() -> String {
    crate::directory::DEFAULT_PATH.into()
}
fn directory_key() -> String {
    crate::directory::DEFAULT_KEY.trim().into()
}
fn github_api() -> String {
    crate::github_queue::DEFAULT_API.into()
}

/// Where tasks come from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum QueueEndpoint {
    /// GitHub issues in `repo` (`owner/name`) labelled `label` (`docs/github-queue.md`). The token
    /// needs only to comment on issues; without one the queue is read-only.
    Github {
        repo: String,
        #[serde(default)]
        token_file: Option<PathBuf>,
        #[serde(default = "default_label")]
        label: String,
        #[serde(default = "default_api")]
        api_url: String,
    },
}

fn default_label() -> String {
    crate::github_queue::DEFAULT_LABEL.into()
}

fn default_api() -> String {
    crate::github_queue::DEFAULT_API.into()
}

impl QueueEndpoint {
    pub fn describe(&self) -> String {
        match self {
            Self::Github { repo, .. } => format!("github:{repo}"),
        }
    }

    pub fn build(&self) -> Result<Arc<dyn QueueClient>> {
        let token = |f: &Option<PathBuf>| f.as_deref().map(crate::secrets::read_secret).transpose();
        Ok(match self {
            Self::Github { repo, token_file, label, api_url } => Arc::new(crate::github_queue::GitHubQueue::new(api_url, repo, label, token(token_file)?)),
        })
    }
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

    /// Writes the config atomically (a temp file renamed into place).
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    /// A safe starter config: strict policy and no projects, so nothing runs until the contributor
    /// adds one.
    pub fn starter(dir: &Path) -> Self {
        Config {
            key_file: dir.join("runner.key"),
            state_dir: dir.join("state"),
            queue_dir: dir.join("queue"),
            queues: vec![],
            poll_secs: default_poll(),
            sandbox: SandboxConfig::Docker { bin: docker_bin(), runtime: None, nested_userns: false, network: None },
            harness: HarnessConfig::Omnigent { provider: ProviderConfig::Anthropic, upstream: None, token_file: None, api_key_file: None },
            policy: Policy {
                daily_token_cap: 100_000,
                project_shares: BTreeMap::new(),
                allowed_kinds: vec![],
                quiet_hours: None,
                review_before_submit: false,
                max_profile: Default::default(),
                abort_margin_pct: 25,
                available_tools: vec!["claude".into(), "omnigent".into()],
                max_input_bytes: 64 * 1024 * 1024,
                reserve_pct: 20,
            },
            projects: BTreeMap::new(),
            environments: BTreeMap::new(),
            sources: BTreeMap::new(),
            directory: DirectoryConfig::default(),
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

    pub fn docker_bin(&self) -> Option<&str> {
        match &self.sandbox {
            SandboxConfig::Docker { bin, .. } => Some(bin),
            SandboxConfig::Dir => None,
        }
    }

    pub fn sandbox_network(&self) -> Option<&str> {
        match &self.sandbox {
            SandboxConfig::Docker { network, .. } => network.as_deref(),
            SandboxConfig::Dir => None,
        }
    }

    pub fn sandbox_nested_userns(&self) -> bool {
        matches!(self.sandbox, SandboxConfig::Docker { nested_userns: true, .. })
    }

    pub fn harness_provider(&self) -> Option<Provider> {
        match &self.harness {
            HarnessConfig::Omnigent { provider, .. } => Some(provider.provider()),
            HarnessConfig::Echo { .. } => None,
        }
    }

    pub fn build_sandbox(&self) -> Box<dyn Sandbox> {
        self.build_sandbox_with(None)
    }

    fn build_sandbox_with(&self, proxy_socket: Option<PathBuf>) -> Box<dyn Sandbox> {
        match &self.sandbox {
            SandboxConfig::Dir => Box::new(DirSandbox { root: self.state_dir.join("work") }),
            SandboxConfig::Docker { bin, runtime, nested_userns, network } => {
                let mut s = DockerSandbox::new();
                s.bin = bin.clone();
                s.runtime = runtime.clone();
                s.network = network.clone();
                s.environments = self.environments.iter().map(|(k, a)| (k.clone(), Environment { image: a.pinned(), network: a.agent.needs_network })).collect();
                if *nested_userns {
                    let path = self.state_dir.join("seccomp-nested-userns.json");
                    let _ = std::fs::create_dir_all(&self.state_dir);
                    let _ = std::fs::write(&path, NESTED_USERNS_PROFILE);
                    s.seccomp_profile = Some(path);
                }
                s.proxy_socket = proxy_socket;
                Box::new(s)
            }
        }
    }

    /// Starts the credential proxy. The secret stays in this process.
    fn start_proxy(&self, provider: ProviderConfig, upstream: &str, token_file: &Path, api_key_file: Option<&Path>) -> Result<Arc<crate::proxy::AuthProxy>> {
        use crate::proxy::Auth;
        use crate::secrets::read_secret;
        let auth = match (provider, api_key_file) {
            (ProviderConfig::Anthropic, Some(f)) => Auth::ApiKey(read_secret(f)?),
            (ProviderConfig::Anthropic, None) => Auth::Bearer { token: read_secret(token_file)?, oauth: true },
            (ProviderConfig::Openai, Some(f)) => Auth::Bearer { token: read_secret(f)?, oauth: false },
            (ProviderConfig::Openai, None) => return Err(Error::Policy("the openai provider needs `api_key_file` (ChatGPT sign-in is not supported by the proxy yet)".into())),
        };
        let dir = self.state_dir.join("proxy");
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        Ok(Arc::new(crate::proxy::AuthProxy::start(&dir.join("p.sock"), upstream, provider.provider(), auth)?))
    }

    pub fn build_queue(&self) -> Result<Arc<dyn QueueClient>> {
        if self.queues.is_empty() {
            return Ok(Arc::new(DirQueue::new(&self.queue_dir)?));
        }
        let endpoints = self.queues.iter().map(QueueEndpoint::build).collect::<Result<Vec<_>>>()?;
        Ok(Arc::new(MultiQueue::new(endpoints)))
    }

    pub fn build(&self) -> Result<DaemonRunner> {
        if self.policy.review_before_submit {
            return Err(Error::Policy("review_before_submit is not supported by the daemon (results are reviewed in the project's pull requests)".into()));
        }
        std::fs::create_dir_all(&self.state_dir)?;
        let mut trusted = TrustedProjects::default();
        for (id, k) in &self.projects {
            let bytes: [u8; 32] = hex::decode(k).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| Error::Verify(format!("bad key for project `{id}`")))?;
            trusted.insert(id, VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Verify(format!("bad key for project `{id}`")))?);
        }
        let mut proxy_socket = None;
        let harness: Box<dyn Harness> = match &self.harness {
            HarnessConfig::Echo { tokens_per_run } => Box::new(EchoHarness { tokens_per_run: *tokens_per_run }),
            HarnessConfig::Omnigent { provider, upstream, token_file, api_key_file } => {
                if !matches!(self.sandbox, SandboxConfig::Docker { .. }) {
                    return Err(Error::Policy("the omnigent harness needs a Docker/Podman sandbox".into()));
                }
                let token_file = token_file.clone().unwrap_or_else(|| self.token_path());
                let proxy = self.start_proxy(*provider, upstream.as_deref().unwrap_or(provider.default_upstream()), &token_file, api_key_file.as_deref())?;
                proxy_socket = Some(proxy.socket().to_path_buf());
                let mut h = OmnigentHarness::new(proxy, provider.provider());
                for (id, a) in &self.environments {
                    h.agents.insert(id.clone(), ApprovedAgent { tar: a.agent_tar_bytes()?, harness: a.agent.harness.clone() });
                }
                Box::new(h)
            }
        };
        let queue = self.build_queue()?;
        Ok(Runner::new(
            self.policy.clone(),
            trusted,
            self.load_or_create_key()?,
            queue,
            harness,
            self.build_sandbox_with(proxy_socket),
            Box::new(NoReview),
            AuditLog::new(self.state_dir.join("audit.jsonl")),
        ))
    }
}
