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

// ----------------------------------------------------------------------------------------------
// Previews: everything `add` and `update` show before asking, computed without changing the
// config, so the CLI and the local UI run the same logic and differ only in how they ask.

use crate::directory::{self, Entry};
use crate::github_queue::GitHubQueue;

/// What a contributor is about to approve for one project.
#[derive(Debug)]
pub struct Preview {
    pub repo: String,
    pub fetched: Fetched,
    pub approval: Approval,
    /// The directory entry the name resolved to, or the entry for this repository if listed.
    pub listed: Option<Entry>,
    /// What `add` would say about the contributor's setup (fence, nested sandbox, token, harness).
    pub notes: Vec<String>,
}

/// The result of re-checking a project.
#[derive(Debug)]
pub enum UpdateCheck {
    UpToDate(String),
    Changed(Box<Changed>),
}

#[derive(Debug)]
pub struct Changed {
    pub old: Option<Approval>,
    pub preview: Preview,
    pub lines: Vec<String>,
}

fn github(api: &str, repo: &str, token_file: Option<&std::path::Path>) -> Result<GitHubQueue> {
    let token = token_file.map(crate::secrets::read_secret).transpose()?;
    Ok(GitHubQueue::new(api, repo, crate::github_queue::DEFAULT_LABEL, token))
}

/// Resolves what the contributor typed: a directory name, or `owner/name` (cross-checked with the
/// directory when listed). Returns the repository, the entry if any, and a note when the
/// directory could not be read for an `owner/name`.
pub fn resolve(cfg: &Config, arg: &str) -> Result<(String, Option<Entry>, Option<String>)> {
    let d = &cfg.directory;
    let lookup = || -> Result<Option<Entry>> {
        let key = directory::parse_key(&d.public_key)?;
        let gh = GitHubQueue::new(&d.api_url, &d.repo, crate::github_queue::DEFAULT_LABEL, None);
        Ok(directory::fetch(&gh, &d.path, &key)?.resolve(arg).cloned())
    };
    match (lookup(), arg.contains('/')) {
        (Ok(Some(e)), _) => Ok((e.repo.clone(), Some(e), None)),
        (Ok(None), true) => Ok((arg.to_string(), None, None)),
        (Ok(None), false) => Err(Error::Policy(format!("no project `{arg}` in the directory (`toto directory list` shows them; or give `owner/name`)"))),
        (Err(e), true) => Ok((arg.to_string(), None, Some(format!("the project directory could not be checked ({e})")))),
        (Err(e), false) => Err(Error::Policy(format!("`{arg}` is not `owner/name`, and the project directory could not be read to look it up: {e}"))),
    }
}

/// Pulls or prebuilds the project's environment and assembles the approval the contributor is
/// shown. `progress` gets a line when something slow starts.
pub fn approval_for(cfg: &Config, repo: &str, f: &Fetched, progress: &mut dyn FnMut(&str)) -> Result<Approval> {
    let bin = cfg.docker_bin().ok_or_else(|| Error::Policy("project environments are container images: configure a docker or podman sandbox first".into()))?;
    let (image, info, prebuilt) = match &f.devcontainer.image {
        Some(image) => {
            progress(&format!("pulling {image}..."));
            (image.clone(), crate::image::inspect(bin, image, true)?, false)
        }
        None => {
            let network = cfg.sandbox_network().ok_or_else(|| Error::Policy("this project publishes no image, so it has to be prebuilt here, and a prebuild needs the fenced network: run `toto net-setup --apply` and set `network` in the sandbox config".into()))?;
            let pb = crate::prebuild::Prebuild { bin: bin.into(), cli: crate::prebuild::DEFAULT_CLI.into(), network: network.into(), work_dir: cfg.state_dir.join("prebuild") };
            progress(&format!("prebuilding {repo} (build, onCreateCommand, updateContentCommand); this can take a while..."));
            let (tag, info) = pb.build(&format!("https://github.com/{repo}.git"), f.commit.as_deref(), &f.devcontainer.toto.id, &f.devcontainer_text, crate::devcontainer::PATH)?;
            (tag, info, true)
        }
    };
    Approval::new(&image, info, &f.agent_files, f.commit.clone(), prebuilt)
}

/// Everything `toto projects add <arg>` shows. Nothing in `cfg` changes.
pub fn preview_add(cfg: &Config, arg: &str, api: &str, token_file: Option<&std::path::Path>, share: u32, progress: &mut dyn FnMut(&str)) -> Result<Preview> {
    let (repo, listed, note) = resolve(cfg, arg)?;
    if let Some(n) = &note {
        progress(&format!("note: {n}"));
    }
    let fetched = fetch(&github(api, &repo, token_file)?)?;
    if let Some(e) = &listed {
        directory::check_key(e, &fetched.devcontainer.toto)?;
    }
    let approval = approval_for(cfg, &repo, &fetched, progress)?;
    let mut trial = cfg.clone();
    let notes = add(&mut trial, &repo, &fetched.devcontainer, approval.clone(), &AddOptions { share, token_file: token_file.map(Into::into) })?;
    Ok(Preview { repo, fetched, approval, listed, notes })
}

/// Applies a preview the contributor confirmed.
pub fn apply_add(cfg: &mut Config, p: &Preview, o: &AddOptions) -> Result<Vec<String>> {
    add(cfg, &p.repo, &p.fetched.devcontainer, p.approval.clone(), o)
}

/// Everything `toto projects update <id>` shows. Nothing in `cfg` changes.
pub fn preview_update(cfg: &Config, id: &str, api: &str, token_file: Option<&std::path::Path>, progress: &mut dyn FnMut(&str)) -> Result<UpdateCheck> {
    let repo = cfg.sources.get(id).cloned().ok_or_else(|| Error::Policy(format!("project `{id}` was not added with `toto projects add`")))?;
    let fetched = fetch(&github(api, &repo, token_file)?)?;
    if cfg.projects.get(id) != Some(&fetched.devcontainer.toto.public_key) {
        return Err(Error::Verify(format!("{repo} now publishes a different key for `{id}`: if you trust the change, `toto projects remove {id}` and add it again")));
    }
    let old = cfg.environments.get(id).cloned();
    if let Some(o) = &old
        && o.prebuilt && o.commit.is_some() && o.commit == fetched.commit
    {
        return Ok(UpdateCheck::UpToDate(format!("commit {}", o.commit.as_deref().unwrap_or(""))));
    }
    let approval = approval_for(cfg, &repo, &fetched, progress)?;
    if let Some(o) = &old
        && o.info.id == approval.info.id && o.agent_hash == approval.agent_hash
    {
        return Ok(UpdateCheck::UpToDate(approval.info.short()));
    }
    let lines = match &old {
        Some(o) => o.diff(&approval),
        None => approval.describe(),
    };
    let preview = Preview { repo, fetched, approval, listed: None, notes: vec![] };
    Ok(UpdateCheck::Changed(Box::new(Changed { old, preview, lines })))
}

/// Applies an update the contributor confirmed.
pub fn apply_update(cfg: &mut Config, id: &str, approval: Approval) {
    cfg.environments.insert(id.to_string(), approval);
}
