//! Usage meter: hard-stops a task that exceeds its estimate by the abort margin.

use crate::{Error, Result};

#[derive(Debug)]
pub struct UsageMeter {
    used: u64,
    limit: u64,
}

impl UsageMeter {
    pub fn new(estimate: u64, margin_pct: u64) -> Self {
        Self { used: 0, limit: estimate.saturating_add(estimate * margin_pct / 100) }
    }

    /// Records usage; errors once the limit is crossed so the harness aborts.
    pub fn record(&mut self, tokens: u64) -> Result<()> {
        self.used = self.used.saturating_add(tokens);
        if self.used > self.limit {
            return Err(Error::Meter { used: self.used, limit: self.limit });
        }
        Ok(())
    }

    pub fn used(&self) -> u64 {
        self.used
    }
}
