//! The few git operations the project side needs, through the `git` binary (plumbing only, so the
//! checkout's working tree and index are never touched).

use crate::{Error, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

pub fn git(dir: &Path, args: &[&str]) -> Result<String> {
    git_env(dir, args, &[])
}

pub fn git_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Result<String> {
    let o = Command::new("git").current_dir(dir).args(args).envs(env.iter().copied()).output()?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        Err(Error::Queue(format!("git {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim())))
    }
}

/// Runs git with `input` on stdin.
pub fn git_input(dir: &Path, args: &[&str], env: &[(&str, &str)], input: &[u8]) -> Result<String> {
    let mut child = Command::new("git").current_dir(dir).args(args).envs(env.iter().copied()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let mut stdin = child.stdin.take().expect("piped");
    let input = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let o = child.wait_with_output()?;
    writer.join().map_err(|_| Error::Queue("git stdin writer panicked".into()))??;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        Err(Error::Queue(format!("git {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim())))
    }
}

/// Whether `origin` has the branch.
pub fn remote_has(dir: &Path, branch: &str) -> Result<bool> {
    Ok(!git(dir, &["ls-remote", "--heads", "origin", &format!("refs/heads/{branch}")])?.is_empty())
}

/// One entry of `git ls-tree -r`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: String,
    pub sha: String,
    pub path: String,
}

/// Every blob under `rev`, recursively (symlinks show mode 120000, submodules are left out).
pub fn ls_tree(dir: &Path, rev: &str) -> Result<Vec<TreeEntry>> {
    let out = Command::new("git").current_dir(dir).args(["ls-tree", "-r", "-z", rev]).output()?;
    if !out.status.success() {
        return Err(Error::Queue(format!("git ls-tree {rev}: {}", String::from_utf8_lossy(&out.stderr).trim())));
    }
    let mut v = vec![];
    for rec in out.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let rec = String::from_utf8_lossy(rec);
        let Some((meta, path)) = rec.split_once('\t') else { continue };
        let mut m = meta.split_whitespace();
        let (Some(mode), Some(kind), Some(sha)) = (m.next(), m.next(), m.next()) else { continue };
        if kind == "blob" {
            v.push(TreeEntry { mode: mode.into(), sha: sha.into(), path: path.into() });
        }
    }
    Ok(v)
}

/// The contents of the given blobs, in order, through one `git cat-file --batch`.
pub fn cat_blobs(dir: &Path, shas: &[String]) -> Result<Vec<Vec<u8>>> {
    if shas.is_empty() {
        return Ok(vec![]);
    }
    let mut child = Command::new("git").current_dir(dir).args(["cat-file", "--batch"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
    let mut stdin = child.stdin.take().expect("piped");
    let list: String = shas.iter().map(|s| format!("{s}\n")).collect();
    let writer = std::thread::spawn(move || stdin.write_all(list.as_bytes()));
    let mut r = BufReader::new(child.stdout.take().expect("piped"));
    let mut out = Vec::with_capacity(shas.len());
    for sha in shas {
        let mut header = String::new();
        r.read_line(&mut header)?;
        let mut h = header.split_whitespace();
        let (_, kind, size) = (h.next(), h.next(), h.next().and_then(|s| s.parse::<usize>().ok()));
        let (Some("blob"), Some(size)) = (kind, size) else {
            return Err(Error::Queue(format!("git cat-file: {sha} is not a blob ({})", header.trim())));
        };
        let mut data = vec![0u8; size];
        r.read_exact(&mut data)?;
        let mut nl = [0u8; 1];
        r.read_exact(&mut nl)?;
        out.push(data);
    }
    writer.join().map_err(|_| Error::Queue("git stdin writer panicked".into()))??;
    child.wait()?;
    Ok(out)
}

/// The tree at `rev` as an input bundle: regular files only (symlinks and submodules are not
/// carried), within `limits`.
pub fn bundle(dir: &Path, rev: &str, limits: crate::archive::Limits) -> Result<Vec<crate::archive::Record>> {
    let entries: Vec<TreeEntry> = ls_tree(dir, rev)?.into_iter().filter(|e| e.mode == "100644" || e.mode == "100755").filter(|e| crate::archive::valid_path(&e.path)).collect();
    if entries.len() > limits.max_files {
        return Err(Error::Schema(format!("{rev} has more than {} files", limits.max_files)));
    }
    let blobs = cat_blobs(dir, &entries.iter().map(|e| e.sha.clone()).collect::<Vec<_>>())?;
    let mut total = 0u64;
    let mut out = vec![];
    for (e, data) in entries.into_iter().zip(blobs) {
        total += data.len() as u64;
        if total > limits.max_total_bytes {
            return Err(Error::Schema(format!("{rev} is larger than the input limit of {} bytes", limits.max_total_bytes)));
        }
        out.push(crate::archive::Record::File { path: e.path, mode: if e.mode == "100755" { 0o755 } else { 0o644 }, data });
    }
    Ok(out)
}
