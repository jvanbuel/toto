//! Harness seam (ADR 4): Omnigent is the primary implementation, behind this trait.

use crate::manifest::TaskManifest;
use crate::meter::UsageMeter;
use crate::sandbox::Workspace;
use crate::Result;

pub trait Harness: Send {
    /// Checks at daemon start that the harness is installed and usable.
    fn probe(&self) -> Result<()> {
        Ok(())
    }

    /// Whether this harness can deliver project-supplied skills and MCP servers (ADR 9).
    /// Tasks carrying context are refused by harnesses that cannot.
    fn supports_context(&self) -> bool {
        false
    }

    /// Runs the task against the workspace, reporting every usage increment to `meter`
    /// and aborting with its error when a limit is hit. Returns the raw output.
    fn run(&self, task: &TaskManifest, ws: &Workspace, meter: &mut UsageMeter) -> Result<String>;
}

impl<T: Harness + ?Sized> Harness for Box<T> {
    fn probe(&self) -> Result<()> {
        (**self).probe()
    }
    fn supports_context(&self) -> bool {
        (**self).supports_context()
    }
    fn run(&self, task: &TaskManifest, ws: &Workspace, meter: &mut UsageMeter) -> Result<String> {
        (**self).run(task, ws, meter)
    }
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

// The Omnigent implementation lives in `omnigent.rs`.
