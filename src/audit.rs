//! Append-only local audit log (JSON lines); also the source of truth for usage today.

use crate::Result;
use chrono::{DateTime, Local, NaiveDate};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: DateTime<Local>,
    pub task_id: String,
    pub project_id: String,
    /// `submitted`, `rejected`, `aborted` or `failed`.
    pub outcome: String,
    pub detail: String,
    pub tokens: u64,
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn append(&self, e: &AuditEntry) -> Result<()> {
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(e)?)?;
        Ok(())
    }

    pub fn entries(&self) -> Result<Vec<AuditEntry>> {
        match fs::read_to_string(&self.path) {
            Ok(s) => s.lines().map(|l| Ok(serde_json::from_str(l)?)).collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
            Err(e) => Err(e.into()),
        }
    }

    /// Tokens used per project on the given local day.
    pub fn usage_on(&self, day: NaiveDate) -> Result<HashMap<String, u64>> {
        let mut m = HashMap::new();
        for e in self.entries()?.into_iter().filter(|e| e.ts.date_naive() == day) {
            *m.entry(e.project_id).or_insert(0) += e.tokens;
        }
        Ok(m)
    }
}
