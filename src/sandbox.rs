//! Sandbox manager (ADR 5: the task workspace lives inside the sandbox).

use crate::manifest::{SandboxProfile, TaskManifest};
use crate::{Error, Result};
use std::path::PathBuf;

/// An isolated workspace for one task. Dropping it must destroy the environment.
pub trait Sandbox {
    /// Creates an environment honouring `profile` and returns the host-visible workspace path.
    fn create(&self, task: &TaskManifest, profile: &SandboxProfile) -> Result<Workspace>;
    fn destroy(&self, ws: Workspace) -> Result<()>;
}

#[derive(Debug)]
pub struct Workspace {
    pub task_id: String,
    /// Host-visible directory (only `DirSandbox`; empty for container sandboxes, which hold
    /// no host filesystem).
    pub path: PathBuf,
    /// Command prefix the harness uses to run a command *inside* the sandbox (ADR 5), e.g.
    /// `docker exec -i <container> <cmd>`. Empty for `DirSandbox`.
    pub exec_prefix: Vec<String>,
}

/// **Not isolating.** A plain temp directory for the spike and tests; it enforces none of the
/// profile. The Docker/microVM implementation (milestone 1) replaces it for real use.
pub struct DirSandbox {
    pub root: PathBuf,
}

impl Sandbox for DirSandbox {
    fn create(&self, task: &TaskManifest, _profile: &SandboxProfile) -> Result<Workspace> {
        let path = self.root.join(&task.id);
        std::fs::create_dir_all(&path)?;
        Ok(Workspace { task_id: task.id.clone(), path, exec_prefix: vec![] })
    }

    fn destroy(&self, ws: Workspace) -> Result<()> {
        std::fs::remove_dir_all(ws.path)?;
        Ok(())
    }
}

/// Hardened Docker/Podman sandbox: one throwaway container per task.
///
/// - no network (`--network none`); manifests asking for an allowlist are refused until an
///   egress proxy exists, so the sandbox fails closed;
/// - read-only root, all capabilities dropped, `no-new-privileges`, non-root user;
/// - no host mounts: the workspace is a size-limited tmpfs inside the container;
/// - CPU, memory and pids limits from the profile;
/// - wall-clock limit: the container's PID 1 is `sleep <timeout>`, so it dies at the deadline.
///
/// Set `runtime` to `runsc` to run under gVisor.
pub struct DockerSandbox {
    /// `docker` or `podman`.
    pub bin: String,
    pub image: String,
    pub runtime: Option<String>,
    pub workspace_mb: u32,
}

impl DockerSandbox {
    pub fn new(image: impl Into<String>) -> Self {
        Self { bin: "docker".into(), image: image.into(), runtime: None, workspace_mb: 512 }
    }

    pub fn container_name(task_id: &str) -> String {
        let safe: String = task_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
        format!("togra-{safe}")
    }

    /// The `run` argument list; pure so the hardening flags are unit-tested without a daemon.
    pub fn run_args(&self, task_id: &str, p: &SandboxProfile) -> Result<Vec<String>> {
        if !p.network_allowlist.is_empty() {
            return Err(Error::Sandbox("network allowlists are not supported yet; refusing to run".into()));
        }
        let mut a: Vec<String> = [
            "run", "-d", "--rm", "--name", &Self::container_name(task_id),
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", "65534:65534",
            "--pids-limit", "256", "--workdir", "/workspace",
        ]
        .map(String::from)
        .into();
        a.extend([
            "--cpus".into(), format!("{:.2}", p.cpu_millis as f64 / 1000.0),
            "--memory".into(), format!("{}m", p.memory_mb),
            "--tmpfs".into(), format!("/workspace:rw,noexec,nosuid,mode=1777,size={}m", self.workspace_mb),
            "--tmpfs".into(), "/tmp:rw,noexec,nosuid,mode=1777,size=64m".into(),
        ]);
        if let Some(rt) = &self.runtime {
            a.extend(["--runtime".into(), rt.clone()]);
        }
        a.extend([self.image.clone(), "sleep".into(), p.timeout_secs.to_string()]);
        Ok(a)
    }

    fn docker(&self, args: &[String]) -> Result<std::process::Output> {
        let out = std::process::Command::new(&self.bin).args(args).output()?;
        if out.status.success() {
            Ok(out)
        } else {
            Err(Error::Sandbox(String::from_utf8_lossy(&out.stderr).trim().to_string()))
        }
    }
}

impl Sandbox for DockerSandbox {
    fn create(&self, task: &TaskManifest, profile: &SandboxProfile) -> Result<Workspace> {
        let args = self.run_args(&task.id, profile)?;
        self.docker(&args)?;
        let name = Self::container_name(&task.id);
        let exec_prefix = vec![self.bin.clone(), "exec".into(), "-i".into(), name];
        Ok(Workspace { task_id: task.id.clone(), path: PathBuf::new(), exec_prefix })
    }

    fn destroy(&self, ws: Workspace) -> Result<()> {
        // `--rm` removes it once stopped; `-t 0` kills immediately. Ignore "already gone".
        let _ = self.docker(&["stop".into(), "-t".into(), "0".into(), Self::container_name(&ws.task_id)]);
        Ok(())
    }
}
