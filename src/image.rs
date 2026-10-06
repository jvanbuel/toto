//! What a contributor can inspect and approve about a project's environment image.
//!
//! A tag can be moved after it was approved, so an approval is bound to the image's *digest*: the
//! runner stores `repo@sha256:...` and always starts tasks from that. What the contributor sees comes
//! from the image itself (its configuration and layer history, i.e. the commands that built it), not
//! from labels or files the project asserts. `toto projects update` shows what changed before the
//! contributor approves a new digest.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageInfo {
    /// `sha256:<hex>` content digest.
    pub digest: String,
    pub user: String,
    pub env: Vec<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub size: u64,
    /// The commands that built each layer, newest first (`docker history --no-trunc`).
    pub history: Vec<String>,
}

/// What the contributor approved for one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvApproval {
    /// The reference the project names (`ghcr.io/acme/env:1.0`).
    pub image: String,
    pub info: ImageInfo,
}

impl EnvApproval {
    /// `repo@sha256:...`: what the runner starts.
    pub fn pinned(&self) -> String {
        format!("{}@{}", repo_of(&self.image), self.info.digest)
    }
}

/// The reference without its tag or digest.
pub fn repo_of(image: &str) -> &str {
    let no_digest = image.split('@').next().unwrap_or(image);
    match no_digest.rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => repo,
        _ => no_digest,
    }
}

fn run(bin: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(bin).args(args).output()?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        Err(Error::Sandbox(format!("{bin} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim())))
    }
}

/// Reads what an approval needs. With `refresh`, a tag is pulled again first, so the result is what
/// the project publishes *now* and not a stale local copy of a tag that has since moved (a digest
/// reference never moves, so it is only pulled if missing).
pub fn inspect(bin: &str, image: &str, refresh: bool) -> Result<ImageInfo> {
    if (refresh && !image.contains('@')) || run(bin, &["image", "inspect", image]).is_err() {
        run(bin, &["pull", "-q", image]).map_err(|e| Error::Sandbox(format!("could not pull `{image}`: {e}")))?;
    }
    let v: serde_json::Value = serde_json::from_str(&run(bin, &["image", "inspect", "--format", "{{json .}}", image])?)?;
    let repo = repo_of(image);
    let digest = match image.split_once('@') {
        Some((_, d)) => d.to_string(),
        None => v["RepoDigests"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str())
            .find_map(|d| d.split_once('@').filter(|(r, _)| *r == repo || r.ends_with(&format!("/{repo}"))).map(|x| x.1.to_string()))
            .ok_or_else(|| Error::Sandbox(format!("`{image}` has no registry digest (was it built locally and never pushed?)")))?,
    };
    let strings = |k: &str| -> Vec<String> { v["Config"][k].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect() };
    let history = run(bin, &["history", "--no-trunc", "--format", "{{.CreatedBy}}", image])?.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    Ok(ImageInfo { digest, user: v["Config"]["User"].as_str().unwrap_or("").into(), env: strings("Env"), entrypoint: strings("Entrypoint"), cmd: strings("Cmd"), size: v["Size"].as_u64().unwrap_or(0), history })
}

/// Human-readable lines for the contributor.
pub fn describe(image: &str, i: &ImageInfo) -> Vec<String> {
    let mut out = vec![
        format!("image       {image}"),
        format!("digest      {} (tasks will run exactly this)", i.digest),
        format!("size        {:.1} MB", i.size as f64 / 1e6),
        format!("user        {}", if i.user.is_empty() { "root in the image (tasks always run as an unprivileged user)" } else { &i.user }),
        format!("entrypoint  {}", if i.entrypoint.is_empty() { "-".into() } else { i.entrypoint.join(" ") }),
        format!("env         {}", i.env.iter().map(|e| e.split('=').next().unwrap_or("")).collect::<Vec<_>>().join(", ")),
        "build steps (newest first):".into(),
    ];
    out.extend(i.history.iter().map(|h| format!("  {}", h.chars().take(220).collect::<String>())));
    out
}

/// What changed between two approvals, as lines (empty if nothing the contributor can see).
pub fn diff(old: &ImageInfo, new: &ImageInfo) -> Vec<String> {
    let mut out = vec![];
    if old.digest != new.digest {
        out.push(format!("digest      {} -> {}", old.digest, new.digest));
    }
    for (what, a, b) in [("user", old.user.clone(), new.user.clone()), ("entrypoint", old.entrypoint.join(" "), new.entrypoint.join(" "))] {
        if a != b {
            out.push(format!("{what:<11} {a:?} -> {b:?}"));
        }
    }
    let (ow, nw): (std::collections::BTreeSet<_>, std::collections::BTreeSet<_>) = (old.env.iter().collect(), new.env.iter().collect());
    out.extend(nw.difference(&ow).map(|e| format!("+ env       {e}")));
    out.extend(ow.difference(&nw).map(|e| format!("- env       {e}")));
    let (oh, nh): (std::collections::BTreeSet<_>, std::collections::BTreeSet<_>) = (old.history.iter().collect(), new.history.iter().collect());
    out.extend(new.history.iter().filter(|h| !oh.contains(h)).map(|h| format!("+ step      {}", h.chars().take(220).collect::<String>())));
    out.extend(old.history.iter().filter(|h| !nh.contains(h)).map(|h| format!("- step      {}", h.chars().take(220).collect::<String>())));
    out
}
