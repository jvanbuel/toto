//! The project directory (ADR 7): a signed list of projects contributors can add by name.
//!
//! The directory is one JSON file in a public repository, signed as a DSSE envelope with the
//! directory maintainers' key. Contributors' runners carry the maintainers' public key (a
//! default built into the binary, overridable in the config), fetch the file, verify it and
//! resolve `toto projects add <name>` to the project's repository. The entry also carries the
//! project's public key, so adding a project checks the key the repository publishes against the
//! key the directory lists: an independent channel for the fingerprint. GitHub is the backend;
//! nothing runs anywhere.
//!
//! Maintainers: `toto directory add owner/name` reads the project's own files into the unsigned
//! `projects.json`, `toto directory sign` produces the signed file to commit.

use crate::devcontainer::Toto;
use crate::dsse::{self, Envelope};
use crate::github_queue::GitHubQueue;
use crate::projects::Fetched;
use crate::{Error, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const PAYLOAD_TYPE: &str = "application/vnd.toto.directory+json";
/// Where the directory lives unless the config says otherwise.
pub const DEFAULT_REPO: &str = "jvanbuel/toto";
pub const DEFAULT_PATH: &str = "directory/projects.json";
/// The directory maintainers' public key (hex Ed25519), from the committed file.
pub const DEFAULT_KEY: &str = include_str!("../directory/maintainers.pub");

/// One project as the directory lists it: enough to show, to find, and to check the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The project id (`customizations.toto.id`), what `toto projects add <name>` takes.
    pub id: String,
    pub name: String,
    /// `owner/name` on GitHub.
    pub repo: String,
    #[serde(default)]
    pub description: String,
    /// Hex Ed25519 public key the project signs tasks with, as its repository published it
    /// when the entry was made.
    pub public_key: String,
    pub kinds: Vec<String>,
    /// Which harness its agent uses, so contributors see which credential it needs.
    #[serde(default)]
    pub harness: String,
    #[serde(default)]
    pub needs_network: bool,
    /// Date the entry was added or last refreshed, `YYYY-MM-DD`.
    #[serde(default)]
    pub added: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Directory {
    pub version: u32,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub projects: Vec<Entry>,
}

impl Default for Directory {
    fn default() -> Self {
        Self { version: 1, updated: String::new(), projects: vec![] }
    }
}

pub fn valid_repo(repo: &str) -> bool {
    matches!(repo.split('/').collect::<Vec<_>>().as_slice(), [o, n] if !o.is_empty() && !n.is_empty() && repo.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/')))
}

fn valid_key(key: &str) -> bool {
    key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit())
}

impl Directory {
    pub fn find(&self, id: &str) -> Option<&Entry> {
        self.projects.iter().find(|e| e.id == id)
    }

    /// The entry whose repository is `repo` (`owner/name`, case-insensitive), if any.
    pub fn by_repo(&self, repo: &str) -> Option<&Entry> {
        self.projects.iter().find(|e| e.repo.eq_ignore_ascii_case(repo))
    }

    /// Resolves what a contributor typed: a project id listed here, or `owner/name`.
    pub fn resolve(&self, arg: &str) -> Option<&Entry> {
        if arg.contains('/') { self.by_repo(arg) } else { self.find(arg) }
    }

    /// Adds or replaces the entry with this id. Returns whether an entry was replaced.
    pub fn upsert(&mut self, entry: Entry) -> bool {
        match self.projects.iter_mut().find(|e| e.id == entry.id) {
            Some(e) => {
                *e = entry;
                true
            }
            None => {
                self.projects.push(entry);
                self.projects.sort_by(|a, b| a.id.cmp(&b.id));
                false
            }
        }
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.projects.len();
        self.projects.retain(|e| e.id != id);
        self.projects.len() != before
    }

    /// Refuses a directory that could not have come from `toto directory add`.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Verify(format!("directory version {} is not supported", self.version)));
        }
        let mut ids = std::collections::BTreeSet::new();
        for e in &self.projects {
            if !crate::devcontainer::valid_id(&e.id) {
                return Err(Error::Verify(format!("directory entry has a bad id `{}`", e.id)));
            }
            if !ids.insert(e.id.as_str()) {
                return Err(Error::Verify(format!("directory lists `{}` twice", e.id)));
            }
            if !valid_repo(&e.repo) {
                return Err(Error::Verify(format!("directory entry `{}` has a bad repository `{}`", e.id, e.repo)));
            }
            if !valid_key(&e.public_key) {
                return Err(Error::Verify(format!("directory entry `{}` has a bad key", e.id)));
            }
            if e.kinds.is_empty() {
                return Err(Error::Verify(format!("directory entry `{}` lists no task kinds", e.id)));
            }
        }
        Ok(())
    }

    /// Signs the directory as a DSSE envelope (the payload is the pretty JSON, base64 inside the
    /// envelope; the unsigned file next to it is the readable copy).
    pub fn sign(&self, key: &SigningKey, today: &str) -> Result<Envelope> {
        self.validate()?;
        let mut d = self.clone();
        d.updated = today.to_string();
        Ok(dsse::sign(PAYLOAD_TYPE, &serde_json::to_vec_pretty(&d)?, key))
    }

    /// Verifies a signed directory file with the maintainers' key.
    pub fn open(bytes: &[u8], key: &VerifyingKey) -> Result<Directory> {
        let env: Envelope = serde_json::from_slice(bytes).map_err(|e| Error::Verify(format!("the directory is not a signed envelope: {e}")))?;
        let payload = env.verify(PAYLOAD_TYPE, key).map_err(|e| Error::Verify(format!("the directory's signature does not verify with the maintainers' key: {e}")))?;
        let d: Directory = serde_json::from_slice(&payload)?;
        d.validate()?;
        Ok(d)
    }

    /// The directory as `projects.json` holds it unsigned (maintainers edit this one).
    pub fn load_unsigned(bytes: &[u8]) -> Result<Directory> {
        let d: Directory = serde_json::from_slice(bytes)?;
        d.validate()?;
        Ok(d)
    }
}

/// Parses a hex public key as the config or the built-in default carries it.
pub fn parse_key(hex_key: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| Error::Verify("the directory key must be 32 bytes of hex".into()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Verify("the directory key is not a valid Ed25519 key".into()))
}

/// Fetches and verifies the directory from `path` in the repository `gh` reads.
pub fn fetch(gh: &GitHubQueue, path: &str, key: &VerifyingKey) -> Result<Directory> {
    let bytes = gh.file(path)?.ok_or_else(|| Error::Verify(format!("no directory at {path} in that repository")))?;
    Directory::open(&bytes, key)
}

/// The entry for a project, from its own files (what `toto projects add` would show).
pub fn entry_from(repo: &str, f: &Fetched, today: &str) -> Result<Entry> {
    if !valid_repo(repo) {
        return Err(Error::Policy(format!("`{repo}` is not `owner/name`")));
    }
    let t: &Toto = &f.devcontainer.toto;
    let agent = crate::agent::summarize(&f.agent_files)?;
    Ok(Entry { id: t.id.clone(), name: t.name.clone(), repo: repo.to_string(), description: t.description.clone(), public_key: t.public_key.clone(), kinds: t.kinds.clone(), harness: agent.harness, needs_network: agent.needs_network, added: today.to_string() })
}

/// The check that makes the directory worth having: the key the repository publishes now must
/// be the key the directory listed. A project cannot swap its key unnoticed.
pub fn check_key(entry: &Entry, published: &Toto) -> Result<()> {
    if entry.public_key != published.public_key {
        return Err(Error::Verify(format!("the directory lists `{}` with key {}…, but {} now publishes {}…; refusing until the directory is updated", entry.id, &entry.public_key[..16], entry.repo, published.public_key.chars().take(16).collect::<String>())));
    }
    if entry.id != published.id {
        return Err(Error::Verify(format!("the directory lists `{}` at {}, but that repository now calls itself `{}`", entry.id, entry.repo, published.id)));
    }
    Ok(())
}

/// One line per project, for `toto directory list`.
pub fn describe(d: &Directory) -> Vec<String> {
    let mut out = vec![format!("{} projects, updated {}", d.projects.len(), if d.updated.is_empty() { "?" } else { &d.updated })];
    for e in &d.projects {
        out.push(format!("{:<20} {:<28} kinds {}  {}{}", e.id, e.repo, e.kinds.join(","), e.harness, if e.needs_network { "  (needs a network)" } else { "" }));
        if !e.description.is_empty() {
            out.push(format!("{:<20} {}", "", e.description));
        }
    }
    out
}
