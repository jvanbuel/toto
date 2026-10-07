//! The sync job's state, on a branch (`toto-state` by default) of the project repository or of a
//! separate, private repository (`state_repo`).
//!
//! The job runs on a fresh machine each time, so it keeps nothing locally: every task, cursor,
//! daily count and cached id is a file on this branch, read at the start of a pass and written at
//! the end, with git plumbing only (the checkout is left alone; the default branch is never
//! written).
//!
//! The branch holds **one commit**, replaced on every pass: history would otherwise grow by a
//! commit per pass, and everyone who clones the project would download it. The replacement is
//! pushed with `--force-with-lease` naming the commit this pass read, which is a compare-and-swap:
//! if another pass replaced it first, the push is refused, this pass stops with
//! [`Error::Concurrent`], and the next one redoes its work.

use super::git::{cat_blobs, ls_tree};
use crate::{Error, Result};
use base64::Engine;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the state branch lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// `origin`, or the URL (or path) of another repository.
    pub remote: String,
    pub branch: String,
    /// A token for an `https://` remote other than `origin` (sent as a basic-auth header, never in
    /// the URL or the command line's arguments shown in logs).
    pub token: Option<String>,
}

impl Location {
    pub fn origin(branch: &str) -> Self {
        Self { remote: "origin".into(), branch: branch.into(), token: None }
    }
}

pub struct Store {
    dir: PathBuf,
    at: Location,
    parent: Option<String>,
    files: BTreeMap<String, Vec<u8>>,
    changed: BTreeSet<String>,
    removed: BTreeSet<String>,
}

const IDENTITY: [(&str, &str); 4] = [
    ("GIT_AUTHOR_NAME", "toto"),
    ("GIT_AUTHOR_EMAIL", "toto@users.noreply.github.com"),
    ("GIT_COMMITTER_NAME", "toto"),
    ("GIT_COMMITTER_EMAIL", "toto@users.noreply.github.com"),
];

impl Store {
    /// Fetches the state branch (it need not exist yet) and reads every file on it.
    pub fn open(dir: &Path, at: Location) -> Result<Self> {
        let mut s = Self { dir: dir.into(), at, parent: None, files: BTreeMap::new(), changed: BTreeSet::new(), removed: BTreeSet::new() };
        let heads = s.git(&["ls-remote", "--heads", &s.at.remote, &format!("refs/heads/{}", s.at.branch)], &[])?;
        if !heads.is_empty() {
            let local = s.local_ref();
            s.git(&["fetch", "-q", "--no-tags", &s.at.remote, &format!("+refs/heads/{}:{local}", s.at.branch)], &[])?;
            let tip = s.git(&["rev-parse", &local], &[])?;
            let entries = ls_tree(dir, &tip)?;
            let blobs = cat_blobs(dir, &entries.iter().map(|e| e.sha.clone()).collect::<Vec<_>>())?;
            s.files = entries.into_iter().map(|e| e.path).zip(blobs).collect();
            s.parent = Some(tip);
        }
        Ok(s)
    }

    /// Runs git in the checkout, with the token's header for an `https://` state remote.
    fn git(&self, args: &[&str], env: &[(&str, &str)]) -> Result<String> {
        let mut cmd = Command::new("git");
        cmd.current_dir(&self.dir);
        if let (Some(token), Some(rest)) = (&self.at.token, self.at.remote.strip_prefix("https://")) {
            let host = rest.split('/').next().unwrap_or_default();
            let key = format!("http.https://{host}/.extraheader");
            let basic = base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
            // An empty value first clears the header actions/checkout set for the project repository.
            cmd.args(["-c", &format!("{key}="), "-c", &format!("{key}=AUTHORIZATION: basic {basic}")]);
        }
        let o = cmd.args(args).envs(env.iter().copied()).output()?;
        if o.status.success() {
            Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else {
            Err(Error::Queue(format!("git {}: {}", args.first().unwrap_or(&""), String::from_utf8_lossy(&o.stderr).trim())))
        }
    }

    fn local_ref(&self) -> String {
        format!("refs/toto/{}", self.at.branch)
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        self.files.get(path).map(|b| serde_json::from_slice(b).map_err(|e| Error::Queue(format!("state file {path}: {e}")))).transpose()
    }

    /// Writes a JSON file; unchanged content is not a change.
    pub fn put<T: Serialize>(&mut self, path: &str, v: &T) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(v)?;
        bytes.push(b'\n');
        self.put_bytes(path, bytes);
        Ok(())
    }

    fn put_bytes(&mut self, path: &str, bytes: Vec<u8>) {
        if self.files.get(path) != Some(&bytes) {
            self.files.insert(path.into(), bytes);
            self.removed.remove(path);
            self.changed.insert(path.into());
        }
    }

    /// Appends one line to a text file (the sync log).
    pub fn append(&mut self, path: &str, line: &str) {
        let mut bytes = self.files.get(path).cloned().unwrap_or_default();
        bytes.extend_from_slice(line.trim_end().as_bytes());
        bytes.push(b'\n');
        self.put_bytes(path, bytes);
    }

    pub fn remove(&mut self, path: &str) {
        if self.files.remove(path).is_some() {
            self.changed.remove(path);
            self.removed.insert(path.into());
        }
    }

    pub fn raw(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// Paths under `prefix`, in order.
    pub fn list(&self, prefix: &str) -> Vec<String> {
        self.files.keys().filter(|p| p.starts_with(prefix)).cloned().collect()
    }

    pub fn has_changes(&self) -> bool {
        !self.changed.is_empty() || !self.removed.is_empty()
    }

    /// Replaces the state branch with one commit holding the current files, if anything changed,
    /// provided the branch is still the commit this pass read. Returns the new commit.
    pub fn commit_and_push(&mut self, message: &str) -> Result<Option<String>> {
        if !self.has_changes() {
            return Ok(None);
        }
        let git_dir = PathBuf::from(self.git(&["rev-parse", "--absolute-git-dir"], &[])?);
        let index = git_dir.join(format!("toto-{}.index", std::process::id()));
        let index_s = index.to_string_lossy().to_string();
        let mut env: Vec<(&str, &str)> = IDENTITY.to_vec();
        env.push(("GIT_INDEX_FILE", &index_s));
        let result = (|| -> Result<String> {
            match &self.parent {
                Some(p) => self.git(&["read-tree", p], &env)?,
                None => self.git(&["read-tree", "--empty"], &env)?,
            };
            for path in &self.removed {
                self.git(&["update-index", "--force-remove", "--", path], &env)?;
            }
            for path in &self.changed {
                let sha = super::git::git_input(&self.dir, &["hash-object", "-w", "--stdin"], &env, &self.files[path])?;
                self.git(&["update-index", "--add", "--cacheinfo", &format!("100644,{sha},{path}")], &env)?;
            }
            let tree = self.git(&["write-tree"], &env)?;
            self.git(&["commit-tree", &tree, "-m", message], &env) // no parent: the branch is one commit
        })();
        let _ = std::fs::remove_file(&index);
        let commit = result?;
        let refname = format!("refs/heads/{}", self.at.branch);
        // Empty expectation: the branch must not exist yet.
        let lease = format!("--force-with-lease={refname}:{}", self.parent.as_deref().unwrap_or(""));
        if let Err(e) = self.git(&["push", "-q", "--no-verify", &lease, &self.at.remote, &format!("{commit}:{refname}")], &[]) {
            let text = e.to_string();
            if ["stale info", "non-fast-forward", "fetch first", "rejected"].iter().any(|m| text.contains(m)) {
                return Err(Error::Concurrent(format!("the {} branch moved while this pass ran", self.at.branch)));
            }
            return Err(e);
        }
        let _ = self.git(&["update-ref", &self.local_ref(), &commit], &[]);
        self.parent = Some(commit.clone());
        self.changed.clear();
        self.removed.clear();
        Ok(Some(commit))
    }
}

/// A file name for an address or name: lower case, anything unusual replaced.
pub fn file_key(s: &str) -> String {
    s.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '@' | '_' | '-') { c } else { '_' }).collect()
}
