//! Sandbox manager (ADR 5: the task workspace lives inside the sandbox).

use crate::manifest::{SandboxProfile, TaskManifest};
use crate::Result;
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
    pub path: PathBuf,
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
        Ok(Workspace { task_id: task.id.clone(), path })
    }

    fn destroy(&self, ws: Workspace) -> Result<()> {
        std::fs::remove_dir_all(ws.path)?;
        Ok(())
    }
}
