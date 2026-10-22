//! Prebuilding a project's environment: the dev container spec's own prebuild phase, done by its
//! reference CLI.
//!
//! Where it runs (ADR 17): in the project's CI, by `toto project image`, which publishes the
//! snapshot as the image contributors pull and approve by digest. Prebuilding on a contributor's
//! machine, for a project that publishes no image, is deprecated: it needs open network access
//! for installs, which only the deprecated `docker` sandbox's iptables fence can confine, and it
//! goes with that sandbox.
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
    /// The network the prebuild runs on: the fenced one on a contributor's machine (installs need
    /// the internet, never the LAN), the default bridge in the project's CI.
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
        let tag = tag_for(project, commit, devcontainer_text);
        let info = self.build_workspace(checkout, &tag, &format!("toto-prebuild={project}"), devcontainer_text, config_rel_path)?;
        Ok((tag, info))
    }

    /// Prebuilds the dev container of the checkout at `workspace` under toto's flags and commits
    /// it as `tag`. What `toto project image` runs in the project's CI.
    pub fn build_workspace(&self, workspace: &Path, tag: &str, label: &str, devcontainer_text: &str, config_rel_path: &str) -> Result<ImageInfo> {
        cli_version(&self.cli).ok_or_else(|| Error::Sandbox(format!("the dev container CLI (`{}`) is not installed: `npm i -g @devcontainers/cli`", self.cli)))?;
        let config = workspace.join(config_rel_path);
        // Next to the original, so the CLI resolves `build.dockerfile` and `context` the same way.
        let override_path = config.with_file_name("toto-prebuild.json");
        std::fs::write(&override_path, sanitize(devcontainer_text, &self.network)?)?;
        let out = run(
            &self.cli,
            &["up", "--workspace-folder", workspace.to_str().unwrap_or("."), "--config", config.to_str().unwrap_or(""), "--override-config", override_path.to_str().unwrap_or(""), "--prebuild", "--id-label", label, "--remove-existing-container", "--docker-path", &self.bin],
            Some(workspace),
        );
        let _ = std::fs::remove_file(&override_path);
        let out = out?;
        let last = out.lines().last().unwrap_or("");
        let v: serde_json::Value = serde_json::from_str(last).map_err(|_| Error::Sandbox(format!("devcontainer up gave no result: {}", last.chars().take(300).collect::<String>())))?;
        let cid = v["containerId"].as_str().ok_or_else(|| Error::Sandbox(format!("devcontainer up failed: {}", v["message"].as_str().unwrap_or(last))))?.to_string();
        let committed = self.commit(&cid, tag);
        let _ = run(&self.bin, &["rm", "-f", &cid], None);
        committed?;
        image::inspect(&self.bin, tag, false)
    }

    /// Commits the prebuilt container as `tag`, starting the way the project's own image does:
    /// the CLI runs the container with its own entrypoint, which `commit` would otherwise keep,
    /// and `commit --change "ENTRYPOINT []"` cannot reset an entrypoint the container overrode.
    /// A metadata-only build step can.
    fn commit(&self, cid: &str, tag: &str) -> Result<()> {
        let base = run(&self.bin, &["inspect", "--format", "{{.Image}}", cid], None)?;
        let field = |f: &str| run(&self.bin, &["image", "inspect", "--format", &format!("{{{{json .Config.{f}}}}}"), &base], None);
        let json_or = |v: String, default: &str| if v == "null" || v.is_empty() { default.to_string() } else { v };
        let (entrypoint, cmd) = (json_or(field("Entrypoint")?, "[]"), json_or(field("Cmd")?, "[\"sh\"]"));
        run(&self.bin, &["commit", cid, tag], None)?;
        let dockerfile = format!("FROM {tag}\nENTRYPOINT {entrypoint}\nCMD {cmd}\n");
        let mut child = Command::new(&self.bin).args(["build", "-q", "-t", tag, "-"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).spawn().map_err(|e| Error::Sandbox(format!("cannot run `{}`: {e}", self.bin)))?;
        std::io::Write::write_all(child.stdin.as_mut().expect("piped"), dockerfile.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(Error::Sandbox(format!("{} build (restoring the entrypoint): {}", self.bin, String::from_utf8_lossy(&out.stderr).trim())));
        }
        Ok(())
    }
}

/// `toto project image`: prebuilds the project's dev container in its own CI and publishes it
/// where `customizations.toto.image` names it. Returns the pushed reference pinned by digest
/// (`<image>@sha256:...`), or the local image id without `push`.
pub fn publish(pb: &Prebuild, workspace: &Path, config_rel_path: &str, push: bool) -> Result<String> {
    let text = std::fs::read_to_string(workspace.join(config_rel_path)).map_err(|e| Error::Policy(format!("{config_rel_path}: {e}")))?;
    let dc = devcontainer::parse(&text)?;
    let target = dc.toto.image.clone().ok_or_else(|| Error::Policy("name the image to publish in customizations.toto.image (e.g. ghcr.io/acme/toto-env:1.0)".into()))?;
    if target.contains('@') {
        return Err(Error::Policy(format!("customizations.toto.image `{target}` must name a tag to publish to, not a digest; contributors pin the digest themselves")));
    }
    let v: serde_json::Value = serde_json::from_str(&devcontainer::strip_jsonc(&text))?;
    if v.get("image").and_then(|i| i.as_str()) == Some(target.as_str()) {
        return Err(Error::Policy(format!("customizations.toto.image `{target}` is also the base `image`; publish toto's snapshot under its own name")));
    }
    let info = pb.build_workspace(workspace, &target, &format!("toto-image={}", dc.toto.id), &text, config_rel_path)?;
    if !push {
        return Ok(info.id);
    }
    run(&pb.bin, &["push", &target], None)?;
    let digests = run(&pb.bin, &["image", "inspect", "--format", "{{json .RepoDigests}}", &target], None)?;
    let repo = target.rsplit_once(':').filter(|(r, t)| !t.contains('/') && !r.is_empty()).map_or(target.as_str(), |(r, _)| r);
    serde_json::from_str::<Vec<String>>(&digests)
        .ok()
        .and_then(|d| d.into_iter().find(|d| d.starts_with(&format!("{repo}@"))))
        .ok_or_else(|| Error::Sandbox(format!("pushed {target}, but the registry reported no digest for it")))
}

