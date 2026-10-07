//! The sync job's state, on a branch of the project repository (`toto-state` by default).
//!
//! The job runs on a fresh machine each time, so it keeps nothing locally: every task, cursor,
//! daily count and cached id is a file on this branch, read at the start of a pass and committed at
//! the end, with git plumbing only (the checkout is left alone). The default branch is never
//! written. If the push is not a fast-forward, another pass got there first: the pass stops with
//! [`Error::Concurrent`] and the next one redoes its work.

use super::git::{cat_blobs, git, git_env, git_input, ls_tree, remote_has};
use crate::{Error, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub struct Store {
    dir: PathBuf,
    branch: String,
    parent: Option<String>,
    files: BTreeMap<String, Vec<u8>>,
    changed: BTreeSet<String>,
}

const IDENTITY: [(&str, &str); 4] = [
    ("GIT_AUTHOR_NAME", "toto"),
    ("GIT_AUTHOR_EMAIL", "toto@users.noreply.github.com"),
    ("GIT_COMMITTER_NAME", "toto"),
    ("GIT_COMMITTER_EMAIL", "toto@users.noreply.github.com"),
];

impl Store {
    /// Fetches the state branch from `origin` (it need not exist yet) and reads every file on it.
    pub fn open(dir: &Path, branch: &str) -> Result<Self> {
        let mut s = Self { dir: dir.into(), branch: branch.into(), parent: None, files: BTreeMap::new(), changed: BTreeSet::new() };
        if remote_has(dir, branch)? {
            let local = s.local_ref();
            git(dir, &["fetch", "-q", "origin", &format!("+refs/heads/{branch}:{local}")])?;
            let tip = git(dir, &["rev-parse", &local])?;
            let entries = ls_tree(dir, &tip)?;
            let blobs = cat_blobs(dir, &entries.iter().map(|e| e.sha.clone()).collect::<Vec<_>>())?;
            s.files = entries.into_iter().map(|e| e.path).zip(blobs).collect();
            s.parent = Some(tip);
        }
        Ok(s)
    }

    fn local_ref(&self) -> String {
        format!("refs/toto/{}", self.branch)
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

    pub fn raw(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// Paths under `prefix`, in order.
    pub fn list(&self, prefix: &str) -> Vec<String> {
        self.files.keys().filter(|p| p.starts_with(prefix)).cloned().collect()
    }

    pub fn has_changes(&self) -> bool {
        !self.changed.is_empty()
    }

    /// Commits the changed files on top of the state branch as it was read, and pushes. Returns
    /// the new commit, or `None` when nothing changed.
    pub fn commit_and_push(&mut self, message: &str) -> Result<Option<String>> {
        if self.changed.is_empty() {
            return Ok(None);
        }
        let git_dir = PathBuf::from(git(&self.dir, &["rev-parse", "--absolute-git-dir"])?);
        let index = git_dir.join(format!("toto-{}.index", std::process::id()));
        let index_s = index.to_string_lossy().to_string();
        let mut env: Vec<(&str, &str)> = IDENTITY.to_vec();
        env.push(("GIT_INDEX_FILE", &index_s));
        let result = (|| -> Result<String> {
            match &self.parent {
                Some(p) => git_env(&self.dir, &["read-tree", p], &env)?,
                None => git_env(&self.dir, &["read-tree", "--empty"], &env)?,
            };
            for path in &self.changed {
                let sha = git_input(&self.dir, &["hash-object", "-w", "--stdin"], &env, &self.files[path])?;
                git_env(&self.dir, &["update-index", "--add", "--cacheinfo", &format!("100644,{sha},{path}")], &env)?;
            }
            let tree = git_env(&self.dir, &["write-tree"], &env)?;
            let mut args = vec!["commit-tree", &tree, "-m", message];
            if let Some(p) = &self.parent {
                args.extend(["-p", p]);
            }
            git_env(&self.dir, &args, &env)
        })();
        let _ = std::fs::remove_file(&index);
        let commit = result?;
        let refspec = format!("{commit}:refs/heads/{}", self.branch);
        if let Err(e) = git(&self.dir, &["push", "-q", "origin", &refspec]) {
            let text = e.to_string();
            if ["non-fast-forward", "fetch first", "rejected", "stale info"].iter().any(|m| text.contains(m)) {
                return Err(Error::Concurrent(format!("the {} branch moved while this pass ran", self.branch)));
            }
            return Err(e);
        }
        let _ = git(&self.dir, &["update-ref", &self.local_ref(), &commit]);
        self.parent = Some(commit.clone());
        self.changed.clear();
        Ok(Some(commit))
    }
}

/// A file name for an address: lower case, anything unusual replaced.
pub fn file_key(s: &str) -> String {
    s.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '@' | '_' | '-') { c } else { '_' }).collect()
}
