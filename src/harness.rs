//! Harness seam (ADR 4): Omnigent is the implementation, behind this trait so tests can use a stub.

use crate::manifest::TaskManifest;
use crate::meter::UsageMeter;
use crate::sandbox::Workspace;
use crate::Result;

pub trait Harness: Send {
    /// Checks at daemon start that the harness is usable.
    fn probe(&self) -> Result<()> {
        Ok(())
    }

    /// Runs the task against the workspace, reporting every usage increment to `meter`
    /// and aborting with its error when a limit is hit. Returns the raw output.
    fn run(&self, task: &TaskManifest, ws: &Workspace, meter: &mut UsageMeter) -> Result<String>;

    /// What the provider last said about the contributor's allowance (`None`: no information).
    fn quota(&self) -> Option<crate::quota::QuotaSignal> {
        None
    }
}

impl<T: Harness + ?Sized> Harness for Box<T> {
    fn probe(&self) -> Result<()> {
        (**self).probe()
    }
    fn quota(&self) -> Option<crate::quota::QuotaSignal> {
        (**self).quota()
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
