//! Queue client (ADR 1: runners pull leases; ADR 8: an open protocol, many endpoints).

use crate::manifest::TaskManifest;
use crate::result::TaskResult;
use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub trait QueueClient {
    /// Tasks currently claimable. The runner picks locally so consent stays on the machine.
    fn available(&self) -> Result<Vec<TaskManifest>>;
    fn claim(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()>;
    fn heartbeat(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()>;
    /// Idempotent per (task, runner): resubmitting the same result is not an error.
    fn submit(&self, result: &TaskResult) -> Result<()>;
    /// Gives a lease back without a result (rejected or aborted tasks).
    fn release(&self, task_id: &str, runner_id: &str) -> Result<()>;
}

/// In-process queue for the demo and tests; mirrors the lease semantics of the real server.
#[derive(Default)]
pub struct InMemoryQueue {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    tasks: Vec<TaskManifest>,
    leases: HashMap<String, (String, Instant)>,
    results: HashMap<(String, String), TaskResult>,
}

impl InMemoryQueue {
    pub fn post(&self, t: TaskManifest) {
        self.state.lock().unwrap().tasks.push(t);
    }

    pub fn results(&self) -> Vec<TaskResult> {
        self.state.lock().unwrap().results.values().cloned().collect()
    }
}

impl QueueClient for InMemoryQueue {
    fn available(&self) -> Result<Vec<TaskManifest>> {
        let s = self.state.lock().unwrap();
        let now = Instant::now();
        let done = |id: &str| s.results.keys().any(|(t, _)| t == id);
        Ok(s.tasks
            .iter()
            .filter(|t| !done(&t.id) && s.leases.get(&t.id).map_or(true, |(_, exp)| *exp <= now))
            .cloned()
            .collect())
    }

    fn claim(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        if let Some((holder, exp)) = s.leases.get(task_id) {
            if *exp > Instant::now() && holder != runner_id {
                return Err(Error::Queue("already leased".into()));
            }
        }
        s.leases.insert(task_id.into(), (runner_id.into(), Instant::now() + lease));
        Ok(())
    }

    fn heartbeat(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        match s.leases.get_mut(task_id) {
            Some((holder, exp)) if holder == runner_id && *exp > Instant::now() => {
                *exp = Instant::now() + lease;
                Ok(())
            }
            _ => Err(Error::Queue("lease lost".into())),
        }
    }

    fn submit(&self, result: &TaskResult) -> Result<()> {
        result.verify()?;
        self.state.lock().unwrap().results.insert((result.task_id.clone(), result.runner_id.clone()), result.clone());
        Ok(())
    }

    fn release(&self, task_id: &str, runner_id: &str) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        if s.leases.get(task_id).is_some_and(|(h, _)| h == runner_id) {
            s.leases.remove(task_id);
        }
        Ok(())
    }
}
