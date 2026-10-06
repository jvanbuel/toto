//! Contributors choose which projects they support (`toto projects add|inspect|update|list|remove`).
//!
//! A project is two files in its repository: `.devcontainer/devcontainer.json` (the environment,
//! with toto's id, key and task kinds under `customizations.toto`) and an Omnigent agent directory
//! (`.toto/agent`). Adding a project shows both and asks once. The approval records exactly what
//! was shown: the image by content and the agent directory by hash, at a commit. The runner starts
//! that image and runs those files, and `update` re-prompts when either changes. Adding also trusts
//! the project's key, gives it a share, allows its task kinds and adds its queue. Nothing else in the
//! contributor's config changes.

use crate::agent::{self, AgentSummary};
use crate::config::{Config, QueueEndpoint};
use crate::devcontainer::{self, Devcontainer};
use crate::image::ImageInfo;
use crate::{Error, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// What the contributor approved for one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    /// The image reference the project names (or `built:<id>` for a prebuild).
    pub image: String,
    pub info: ImageInfo,
    /// The agent directory as a base64 tar, exactly as approved.
    pub agent_tar: String,
    pub agent_hash: String,
    pub agent: AgentSummary,
    /// Repository commit the files were read at.
    #[serde(default)]
    pub commit: Option<String>,
    /// The image was built on this machine from the project's devcontainer config.
    #[serde(default)]
    pub prebuilt: bool,
}

impl Approval {
    pub fn new(image: &str, info: ImageInfo, files: &BTreeMap<String, Vec<u8>>, commit: Option<String>, prebuilt: bool) -> Result<Self> {
        let summary = agent::summarize(files)?;
        let tar = agent::pack(files)?;
        Ok(Self { image: image.into(), info, agent_hash: agent::hash(&tar), agent_tar: base64::engine::general_purpose::STANDARD.encode(&tar), agent: summary, commit, prebuilt })
    }

    /// `repo@digest` or the image id: what the runner starts.
    pub fn pinned(&self) -> String {
        self.info.pinned(&self.image)
    }

    pub fn agent_tar_bytes(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD.decode(&self.agent_tar).map_err(|_| Error::Policy("stored agent directory is not valid base64".into()))
    }

    /// Everything the contributor is approving, as lines.
    pub fn describe(&self) -> Vec<String> {
        let mut out = vec![format!("commit      {}", self.commit.as_deref().unwrap_or("unknown"))];
        out.extend(crate::image::describe(&self.image, &self.info));
        out.push(String::new());
        out.push(format!("agent directory ({} files, hash {}…):", self.agent.skills.len() + 1, &self.agent_hash[..12]));
        out.extend(self.agent.describe().into_iter().map(|l| format!("  {l}")));
        out
    }

    /// What changed between two approvals of the same project.
    pub fn diff(&self, new: &Approval) -> Vec<String> {
        let mut out = vec![];
        if self.image != new.image {
            out.push(format!("image       {} -> {}", self.image, new.image));
        }
        out.extend(crate::image::diff(&self.info, &new.info));
        if self.agent_hash != new.agent_hash {
            out.push(format!("agent       changed ({}… -> {}…):", &self.agent_hash[..12], &new.agent_hash[..12]));
            out.extend(new.agent.describe().into_iter().map(|l| format!("  {l}")));
        }
        out
    }
}

/// The project as read from its repository at one commit.
#[derive(Debug)]
pub struct Fetched {
    pub devcontainer: Devcontainer,
    pub devcontainer_text: String,
    pub agent_files: BTreeMap<String, Vec<u8>>,
    pub agent_dir: String,
    pub commit: Option<String>,
}

/// Reads the project's files through `repo` (a GitHub client or a test double).
pub trait RepoFiles {
    fn head_commit(&self) -> Result<Option<String>>;
    fn file(&self, path: &str, commit: Option<&str>) -> Result<Option<Vec<u8>>>;
    /// All files under `dir`, paths relative to it.
    fn tree(&self, dir: &str, commit: Option<&str>) -> Result<BTreeMap<String, Vec<u8>>>;
}

pub fn fetch(repo: &dyn RepoFiles) -> Result<Fetched> {
    let commit = repo.head_commit()?;
    let c = commit.as_deref();
    let (text, _) = [devcontainer::PATH, devcontainer::ALT_PATH]
        .iter()
        .find_map(|p| repo.file(p, c).transpose().map(|r| r.map(|b| (b, *p))))
        .transpose()?
        .ok_or_else(|| Error::Policy(format!("the repository has no {} (is it a toto project?)", devcontainer::PATH)))?;
    let text = String::from_utf8(text).map_err(|_| Error::Policy("devcontainer.json is not UTF-8".into()))?;
    let dc = devcontainer::parse(&text)?;
    let agent_dir = dc.toto.agent.clone().unwrap_or_else(|| agent::DEFAULT_AGENT_DIR.into());
    let agent_files = repo.tree(&agent_dir, c)?;
    if agent_files.is_empty() {
        return Err(Error::Policy(format!("the repository has no agent directory at {agent_dir} (an Omnigent agent: config.yaml and skills/)")));
    }
    Ok(Fetched { devcontainer: dc, devcontainer_text: text, agent_files, agent_dir, commit })
}

pub struct AddOptions {
    pub share: u32,
    /// File with the contributor's GitHub token (to claim and answer tasks); `None` leaves it unset.
    pub token_file: Option<PathBuf>,
}

/// Adds the project to `cfg` with the approval the contributor confirmed; returns notes for them.
pub fn add(cfg: &mut Config, repo: &str, dc: &Devcontainer, approval: Approval, o: &AddOptions) -> Result<Vec<String>> {
    let t = &dc.toto;
    if cfg.projects.get(&t.id).is_some_and(|k| *k != t.public_key) {
        return Err(Error::Policy(format!("project `{}` is already configured with a different key; remove it first if you mean to switch", t.id)));
    }
    let mut notes = vec![];
    cfg.projects.insert(t.id.clone(), t.public_key.clone());
    cfg.policy.project_shares.insert(t.id.clone(), o.share.max(1));
    cfg.sources.insert(t.id.clone(), repo.to_string());
    for k in &t.kinds {
        if !cfg.policy.allowed_kinds.contains(k) {
            cfg.policy.allowed_kinds.push(k.clone());
        }
    }
    if !cfg.queues.iter().any(|q| matches!(q, QueueEndpoint::Github { repo: r, .. } if r == repo)) {
        cfg.queues.push(QueueEndpoint::Github { repo: repo.into(), token_file: o.token_file.clone(), label: crate::github_queue::DEFAULT_LABEL.into(), api_url: crate::github_queue::DEFAULT_API.into() });
    }
    if approval.agent.needs_network && cfg.sandbox_network().is_none() {
        notes.push("this project's tasks need a network: run `toto net-setup --apply` and set `network` in the sandbox config, or its tasks will be refused".into());
    }
    if approval.agent.needs_nested_sandbox() && !cfg.sandbox_nested_userns() {
        notes.push("this project's agent uses Omnigent's own sandbox inside the container: set `nested_userns: true` in the sandbox config, or its tools will fail".into());
    }
    if let Some(p) = approval.agent.provider()
        && cfg.harness_provider().is_some_and(|mine| mine != p)
    {
        notes.push(format!("this project's harness `{}` needs {p:?} credentials; your harness is configured for {:?}, so its tasks will be refused", approval.agent.harness, cfg.harness_provider().unwrap()));
    }
    cfg.environments.insert(t.id.clone(), approval);
    if cfg.queues.iter().any(|q| matches!(q, QueueEndpoint::Github { repo: r, token_file: None, .. } if r == repo)) {
        notes.push("no GitHub token configured for this queue: set `token_file` (a token that may comment on issues) so your runner can claim and answer tasks".into());
    }
    Ok(notes)
}

/// Stops supporting a project: its key, share, source, approval and queue entry go. Kinds stay in
/// the policy (other projects may use them).
pub fn remove(cfg: &mut Config, id: &str) -> Result<String> {
    if cfg.projects.remove(id).is_none() {
        return Err(Error::Policy(format!("project `{id}` is not configured")));
    }
    cfg.policy.project_shares.remove(id);
    cfg.environments.remove(id);
    let repo = cfg.sources.remove(id);
    if let Some(repo) = repo.filter(|r| !cfg.sources.values().any(|o| o == r)) {
        cfg.queues.retain(|q| !matches!(q, QueueEndpoint::Github { repo: r, .. } if *r == repo));
    }
    Ok("removed; allowed kinds were left in your policy".into())
}

pub fn list(cfg: &Config) -> Vec<String> {
    cfg.projects
        .iter()
        .map(|(id, key)| {
            let share = cfg.policy.project_shares.get(id).copied().unwrap_or(0);
            let from = cfg.sources.get(id).map_or(String::new(), |r| format!("  github:{r}"));
            let env = cfg.environments.get(id).map_or("  (no approved environment)".to_string(), |a| format!("  {} {}  agent {}…  {}", a.image, a.info.short(), &a.agent_hash[..8], a.agent.harness));
            format!("{id}  key {}…  share {share}{from}{env}", key.chars().take(16).collect::<String>())
        })
        .collect()
}
