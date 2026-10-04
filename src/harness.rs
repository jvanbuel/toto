//! Harness seam (ADR 4): Omnigent is the primary implementation, behind this trait.

use crate::manifest::TaskManifest;
use crate::meter::UsageMeter;
use crate::sandbox::Workspace;
use crate::Result;

pub trait Harness {
    /// Runs the task against the workspace, reporting every usage increment to `meter`
    /// and aborting with its error when a limit is hit. Returns the raw output.
    fn run(&self, task: &TaskManifest, ws: &Workspace, meter: &mut UsageMeter) -> Result<String>;
}

/// Deterministic stand-in that echoes the prompt; used by the demo and tests.
pub struct EchoHarness {
    pub tokens_per_run: u64,
}

impl Harness for EchoHarness {
    fn run(&self, task: &TaskManifest, _ws: &Workspace, meter: &mut UsageMeter) -> Result<String> {
        meter.record(self.tokens_per_run)?;
        Ok(format!("echo: {}", task.prompt))
    }
}

// TODO(milestone 1): `OmnigentHarness` — start/supervise `omnigent server --background` and
// drive it over its local API, routing command execution into the sandbox (ADR 4, ADR 5).
