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
        /// Path to the static `toto-mcp-exec` binary, mounted read-only into the container.
        #[serde(default)]
        bridge: Option<PathBuf>,
        /// Use toto's seccomp profile that allows a nested bubblewrap, so tools like Omnigent can
        /// run their own sandbox inside the container (see `profiles/README.md`). Opt-in.
        #[serde(default)]
        nested_userns: bool,
        #[serde(default)]
        network: bool,
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
        /// Token from `claude setup-token`, stored by `toto login` (default: <state_dir>/claude.token).
        #[serde(default)]
        token_file: Option<PathBuf>,
        #[serde(default)]
        model: Option<String>,
        /// `host` (default): agent on the host, tools in the container over MCP (ADR 10, 11).
        /// `container`: agent inside the container behind the credential proxy (ADR 12).
        #[serde(default)]
        placement: PlacementConfig,
        /// API origin the proxy forwards to (container placement).
        #[serde(default = "default_upstream")]
        upstream: String,
        /// Agent binary mounted into the container; default: the `claude` found on PATH.
        #[serde(default)]
        agent_binary: Option<PathBuf>,
        /// Companion files mounted next to the agent executable (container placement).
        #[serde(default)]
        agent_extra_files: Vec<PathBuf>,
        /// Use an API key (from this file) instead of the subscription token (container placement).
        #[serde(default)]
        api_key_file: Option<PathBuf>,
    },
    /// Omnigent in no-network mode (see `omnigent.rs`); needs sandbox `dir` or `bwrap`.
    Omnigent {
        #[serde(default = "omnigent_bin")]
        bin: String,
        #[serde(default = "omnigent_url")]
        server_url: String,
        #[serde(default = "omnigent_harness")]
        harness: String,
        /// `host` (default) or `container`: Omnigent and the agent inside the sandbox image,
        /// behind the credential proxy (ADR 12). The image must contain `omnigent`.
        #[serde(default)]
        placement: PlacementConfig,
        /// Which API the proxy fronts (container placement).
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
        /// Agent CLI files mounted under /toto/agent and put on PATH (e.g. codex and its companion
        /// `codex-code-mode-host`), for harnesses whose CLI is not in the image.
        #[serde(default)]
        agent_files: Vec<PathBuf>,
        /// Model for the agent (`executor.model`); needed in container placement.
        #[serde(default)]
        model: Option<String>,
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
    fn provider(self) -> crate::proxy::Provider {
        match self {
            ProviderConfig::Anthropic => crate::proxy::Provider::Anthropic,
            ProviderConfig::Openai => crate::proxy::Provider::OpenAi,
        }
    }

    fn default_upstream(self) -> &'static str {
        match self {
            ProviderConfig::Anthropic => "https://api.anthropic.com",
            ProviderConfig::Openai => "https://api.openai.com",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlacementConfig {
    #[default]
    Host,
    Container,
}

fn default_upstream() -> String {
    "https://api.anthropic.com".into()
}

fn which_claude() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join("claude")).find(|c| c.is_file())).and_then(|c| std::fs::canonicalize(c).ok())
}

/// Docker's default seccomp profile plus what a nested bubblewrap needs (generated; see profiles/).
const NESTED_USERNS_PROFILE: &str = include_str!("../profiles/seccomp-nested-userns.json");

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
            sandbox: SandboxConfig::Docker { bin: docker_bin(), image: "alpine".into(), runtime: None, bridge: None, nested_userns: false, network: false },
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
                allow_context: false,
                allow_stdio_mcp: false,
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
        self.build_sandbox_with(None, None)
    }

    fn build_sandbox_with(&self, proxy_socket: Option<PathBuf>, agent: Option<Vec<PathBuf>>) -> Box<dyn Sandbox> {
        let work = self.state_dir.join("work");
        match &self.sandbox {
            SandboxConfig::Dir => Box::new(DirSandbox { root: work }),
            SandboxConfig::Bwrap => Box::new(BwrapSandbox::new(work)),
            SandboxConfig::Docker { bin, image, runtime, bridge, nested_userns, network } => {
                let mut s = DockerSandbox::new(image);
                s.bin = bin.clone();
                s.runtime = runtime.clone();
                s.bridge = bridge.clone();
                s.network = *network;
                if *nested_userns {
                    let path = self.state_dir.join("seccomp-nested-userns.json");
                    let _ = std::fs::create_dir_all(&self.state_dir);
                    let _ = std::fs::write(&path, NESTED_USERNS_PROFILE);
                    s.seccomp_profile = Some(path);
                }
                s.proxy_socket = proxy_socket;
                s.agent_files = agent.unwrap_or_default();
                Box::new(s)
            }
        }
    }

    /// Starts the credential proxy for container placements. The secret stays in this process.
    fn start_proxy(&self, provider: ProviderConfig, upstream: &str, token_file: &Path, api_key_file: Option<&Path>) -> Result<std::sync::Arc<crate::proxy::AuthProxy>> {
        use crate::proxy::Auth;
        let auth = match (provider, api_key_file) {
            (ProviderConfig::Anthropic, Some(f)) => Auth::ApiKey(crate::claude_cli::read_secret(f)?),
            (ProviderConfig::Anthropic, None) => Auth::Bearer { token: crate::claude_cli::read_secret(token_file)?, oauth: true },
            (ProviderConfig::Openai, Some(f)) => Auth::Bearer { token: crate::claude_cli::read_secret(f)?, oauth: false },
            (ProviderConfig::Openai, None) => return Err(Error::Policy("the openai provider needs `api_key_file` (ChatGPT sign-in is not supported by the proxy yet)".into())),
        };
        let dir = self.state_dir.join("proxy");
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        Ok(std::sync::Arc::new(crate::proxy::AuthProxy::start(&dir.join("p.sock"), upstream, provider.provider(), auth)?))
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
        let (mut proxy_socket, mut agent): (Option<PathBuf>, Option<Vec<PathBuf>>) = (None, None);
        let harness: Box<dyn Harness> = match &self.harness {
            HarnessConfig::Echo { tokens_per_run } => Box::new(EchoHarness { tokens_per_run: *tokens_per_run }),
            HarnessConfig::Claude { bin, token_file, model, placement, upstream, agent_binary, agent_extra_files, api_key_file } => {
                if !matches!(self.sandbox, SandboxConfig::Docker { bridge: Some(_), .. }) {
                    return Err(Error::Policy("the claude harness needs a Docker/Podman sandbox with `bridge` set to the static toto-mcp-exec binary".into()));
                }
                let token_file = token_file.clone().unwrap_or_else(|| self.token_path());
                let mut h = ClaudeCliHarness::new(&self.state_dir, token_file.clone())?;
                h.bin = bin.clone();
                h.model = model.clone();
                if *placement == PlacementConfig::Container {
                    // The credential stays with this process: the proxy adds it to model calls.
                    let proxy = self.start_proxy(ProviderConfig::Anthropic, upstream, &token_file, api_key_file.as_deref())?;
                    proxy_socket = Some(proxy.socket().to_path_buf());
                    let exe = agent_binary.clone().or_else(which_claude).ok_or_else(|| Error::Policy("no `claude` binary found for the container; set `agent_binary`".into()))?;
                    h.agent_name = exe.file_name().unwrap_or_default().to_string_lossy().into_owned();
                    agent = Some(std::iter::once(exe).chain(agent_extra_files.iter().cloned()).collect::<Vec<_>>());
                    h = h.in_container(proxy);
                }
                Box::new(h)
            }
            HarnessConfig::Omnigent { bin, server_url, harness, placement, provider, upstream, token_file, api_key_file, agent_files, model } => {
                if matches!(self.sandbox, SandboxConfig::Docker { bridge: None, .. }) {
                    return Err(Error::Policy("the omnigent harness with a container sandbox needs the exec bridge: set `bridge` to the static toto-mcp-exec binary (or use sandbox `dir` or `bwrap`)".into()));
                }
                let mut h = OmnigentHarness::new(&self.state_dir)?;
                h.bin = bin.clone();
                h.server_url = server_url.clone();
                h.harness = harness.clone();
                h.model = model.clone();
                if *placement == PlacementConfig::Container {
                    if !matches!(self.sandbox, SandboxConfig::Docker { .. }) {
                        return Err(Error::Policy("omnigent container placement needs a Docker/Podman sandbox whose image contains `omnigent`".into()));
                    }
                    let token_file = token_file.clone().unwrap_or_else(|| self.token_path());
                    let proxy = self.start_proxy(*provider, upstream.as_deref().unwrap_or(provider.default_upstream()), &token_file, api_key_file.as_deref())?;
                    proxy_socket = Some(proxy.socket().to_path_buf());
                    agent = (!agent_files.is_empty()).then(|| agent_files.clone());
                    h = h.in_container(proxy, provider.provider());
                }
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
            self.build_sandbox_with(proxy_socket, agent),
            Box::new(NoReview),
            AuditLog::new(self.state_dir.join("audit.jsonl")),
        ))
    }
}
