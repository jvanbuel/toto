//! Prebuilding a project's environment on the contributor's machine, when the project publishes
//! no image: the dev container spec's own prebuild phase, done by its reference CLI.
//!
//! The project's `devcontainer.json` is handed to `devcontainer up --prebuild` through an
//! *override config*: its `build`/`features`/`onCreateCommand`/`updateContentCommand` kept, the
//! keys that act on the host dropped (`runArgs`, `mounts`, `privileged`, ...), and toto's own
//! `runArgs` injected (no capabilities, no privilege escalation, the fenced network). The CLI builds
//! the image, runs the two prebuild lifecycle commands in it, and toto commits the result as a local
//! image pinned by its id. Tasks then start from that snapshot offline, and `postCreateCommand` and
//! later never run, as Codespaces prebuilds define it.
//!
//! Needs Node and `@devcontainers/cli` (`npm i -g @devcontainers/cli`); without them only projects
//! with a published image can be added.

use crate::devcontainer::{self, HOST_KEYS};
use crate::image::{self, ImageInfo};
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DEFAULT_CLI: &str = "devcontainer";

pub struct Prebuild {
    /// `docker` or `podman`.
    pub bin: String,
    /// The dev container CLI.
    pub cli: String,
    /// The fenced network the prebuild runs on (installs need the internet, never the LAN).
    pub network: String,
    /// Scratch directory for checkouts.
    pub work_dir: PathBuf,
}

/// The CLI's version, if it runs.
pub fn cli_version(cli: &str) -> Option<String> {
    let o = Command::new(cli).arg("--version").output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|v| !v.is_empty())
}

/// The override config: the project's build and prebuild commands under toto's run flags.
pub fn sanitize(devcontainer_text: &str, network: &str) -> Result<String> {
    let mut v: serde_json::Value = serde_json::from_str(&devcontainer::strip_jsonc(devcontainer_text)).map_err(|e| Error::Policy(format!("devcontainer.json: {e}")))?;
    let obj = v.as_object_mut().ok_or_else(|| Error::Policy("devcontainer.json: not an object".into()))?;
    for k in HOST_KEYS.iter().chain(["postCreateCommand", "postStartCommand", "postAttachCommand", "forwardPorts", "appPort", "portsAttributes", "otherPortsAttributes", "hostRequirements", "userEnvProbe", "updateRemoteUserUID"].iter()) {
        obj.remove(*k);
    }
    obj.insert("runArgs".into(), serde_json::json!(["--cap-drop=ALL", "--security-opt=no-new-privileges", format!("--network={network}")]));
    // No user-specific state: a prebuild is the same for every contributor.
    obj.insert("updateRemoteUserUID".into(), serde_json::Value::Bool(false));
    Ok(serde_json::to_string_pretty(&v)?)
}

fn run(prog: &str, args: &[&str], cwd: Option<&Path>) -> Result<String> {
    let mut c = Command::new(prog);
    c.args(args);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    let o = c.output().map_err(|e| Error::Sandbox(format!("cannot run `{prog}`: {e}")))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        let err = String::from_utf8_lossy(&o.stderr);
        let out = String::from_utf8_lossy(&o.stdout);
        let tail: Vec<&str> = err.lines().chain(out.lines()).rev().take(6).collect();
        Err(Error::Sandbox(format!("{prog} {}: {}", args.join(" "), tail.into_iter().rev().collect::<Vec<_>>().join(" | "))))
    }
}

/// The local tag a prebuild gets: `toto/<project>:<commit or hash>`.
pub fn tag_for(project: &str, commit: Option<&str>, devcontainer_text: &str) -> String {
    let short = commit.map(|c| c.chars().take(12).collect::<String>()).unwrap_or_else(|| crate::archive::sha256_hex(devcontainer_text.as_bytes())[..12].to_string());
    format!("toto/{project}:{short}")
}

impl Prebuild {
    /// Clones `repo_url` at `commit` (or its default branch), prebuilds the dev container under
    /// toto's flags, commits the container as `tag_for(...)` and returns its reference and info.
    pub fn build(&self, repo_url: &str, commit: Option<&str>, project: &str, devcontainer_text: &str, config_rel_path: &str) -> Result<(String, ImageInfo)> {
        cli_version(&self.cli).ok_or_else(|| Error::Sandbox(format!("the dev container CLI (`{}`) is not installed: `npm i -g @devcontainers/cli`, or ask the project to publish an image", self.cli)))?;
        std::fs::create_dir_all(&self.work_dir)?;
        let checkout = self.work_dir.join(format!("{project}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&checkout);
        run("git", &["clone", "-q", "--depth", "1", repo_url, checkout.to_str().unwrap_or(".")], None)?;
        if let Some(c) = commit {
            run("git", &["fetch", "-q", "--depth", "1", "origin", c], Some(&checkout))?;
            run("git", &["checkout", "-q", c], Some(&checkout))?;
        }
        let result = self.build_checkout(&checkout, project, commit, devcontainer_text, config_rel_path);
        let _ = std::fs::remove_dir_all(&checkout);
        result
    }

    fn build_checkout(&self, checkout: &Path, project: &str, commit: Option<&str>, devcontainer_text: &str, config_rel_path: &str) -> Result<(String, ImageInfo)> {
        let config = checkout.join(config_rel_path);
        // Next to the original, so the CLI resolves `build.dockerfile` and `context` the same way.
        let override_path = config.with_file_name("toto-prebuild.json");
        std::fs::write(&override_path, sanitize(devcontainer_text, &self.network)?)?;
        let label = format!("toto-prebuild={project}");
        let out = run(
            &self.cli,
            &["up", "--workspace-folder", checkout.to_str().unwrap_or("."), "--config", config.to_str().unwrap_or(""), "--override-config", override_path.to_str().unwrap_or(""), "--prebuild", "--id-label", &label, "--remove-existing-container", "--docker-path", &self.bin],
            Some(checkout),
        )?;
        let last = out.lines().last().unwrap_or("");
        let v: serde_json::Value = serde_json::from_str(last).map_err(|_| Error::Sandbox(format!("devcontainer up gave no result: {}", last.chars().take(300).collect::<String>())))?;
        let cid = v["containerId"].as_str().ok_or_else(|| Error::Sandbox(format!("devcontainer up failed: {}", v["message"].as_str().unwrap_or(last))))?.to_string();
        let tag = tag_for(project, commit, devcontainer_text);
        let committed = run(&self.bin, &["commit", "--change", "ENTRYPOINT []", "--change", "CMD [\"sh\"]", &cid, &tag], None);
        let _ = run(&self.bin, &["rm", "-f", &cid], None);
        committed?;
        let info = image::inspect(&self.bin, &tag, false)?;
        Ok((tag, info))
    }
}
