//! The async daemon: poll, run, heartbeat, shut down cleanly. Set and forget.
//!
//! The lifecycle in `Runner::tick` is synchronous (it drives subprocesses), so each tick runs
//! on tokio's blocking pool while async tasks handle polling, lease heartbeats, signals and
//! the status file.

use crate::config::{Config, DaemonRunner};
use crate::queue::QueueClient;
use crate::runner::Tick;
use crate::Result;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Snapshot written to `<state_dir>/status.json` for the TUI and `toto status`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Status {
    pub state: String,
    pub task: Option<String>,
    pub ticks: u64,
    pub submitted: u64,
    pub dropped: u64,
    pub last_error: Option<String>,
    pub updated: String,
}

impl Status {
    pub fn read(state_dir: &Path) -> Option<Status> {
        serde_json::from_slice(&std::fs::read(state_dir.join("status.json")).ok()?).ok()
    }

    fn write(&mut self, state_dir: &Path, state: &str, task: Option<String>) {
        self.state = state.into();
        self.task = task;
        self.updated = Local::now().to_rfc3339();
        let tmp = state_dir.join("status.json.tmp");
        if let Ok(b) = serde_json::to_vec_pretty(self)
            && std::fs::write(&tmp, b).is_ok() {
                let _ = std::fs::rename(tmp, state_dir.join("status.json"));
            }
    }
}

const MAX_BACKOFF: Duration = Duration::from_secs(300);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// Runs until `shutdown` resolves. Fails fast if the configured sandbox does not work.
pub async fn run(cfg: Config, shutdown: impl Future<Output = ()>) -> Result<()> {
    let runner = cfg.build()?;
    runner.sandbox.probe()?;
    runner.harness.probe()?;
    run_runner(runner, cfg, shutdown).await
}

async fn run_runner(runner: DaemonRunner, cfg: Config, shutdown: impl Future<Output = ()>) -> Result<()> {
    tokio::pin!(shutdown);
    let (queue, runner_id, lease, current) = (runner.queue.clone(), runner.runner_id(), runner.lease, runner.current_lease.clone());
    let heartbeat = tokio::spawn(heartbeat_loop(queue.clone(), runner_id.clone(), lease, current.clone()));
    let runner = Arc::new(Mutex::new(runner));
    let (poll, mut status, mut backoff) = (Duration::from_secs(cfg.poll_secs.max(1)), Status::default(), Duration::ZERO);
    status.write(&cfg.state_dir, "idle", None);

    'main: loop {
        let r = runner.clone();
        let mut tick = tokio::task::spawn_blocking(move || r.lock().unwrap().tick(Local::now()));
        status.write(&cfg.state_dir, "polling", None);
        let outcome = tokio::select! {
            res = &mut tick => res.expect("tick panicked"),
            _ = &mut shutdown => {
                // Let an in-flight task finish within the grace period, then give the lease back.
                if tokio::time::timeout(SHUTDOWN_GRACE, &mut tick).await.is_err() {
                    let held = current.lock().unwrap().clone();
                    if let Some(id) = held {
                        let _ = queue.release(&id, &runner_id);
                    }
                }
                break 'main;
            }
        };
        status.ticks += 1;
        let wait = match outcome {
            Ok(Tick::Submitted(id)) => {
                status.submitted += 1;
                backoff = Duration::ZERO;
                status.write(&cfg.state_dir, "idle", Some(id));
                Duration::ZERO
            }
            Ok(Tick::Dropped(id)) => {
                status.dropped += 1;
                backoff = Duration::ZERO;
                status.write(&cfg.state_dir, "idle", Some(id));
                Duration::ZERO
            }
            Ok(Tick::Idle) => {
                backoff = Duration::ZERO;
                status.write(&cfg.state_dir, "idle", None);
                poll
            }
            Err(e) => {
                backoff = (backoff * 2).clamp(poll, MAX_BACKOFF);
                status.last_error = Some(e.to_string());
                status.write(&cfg.state_dir, "backoff", None);
                backoff
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = &mut shutdown => break 'main,
        }
    }
    heartbeat.abort();
    status.write(&cfg.state_dir, "stopped", None);
    Ok(())
}

/// Renews the lease of whatever task is running, a third of the way through each lease window.
async fn heartbeat_loop(queue: Arc<dyn QueueClient>, runner_id: String, lease: Duration, current: Arc<Mutex<Option<String>>>) {
    let mut every = tokio::time::interval(lease / 3);
    every.tick().await;
    loop {
        every.tick().await;
        let held = current.lock().unwrap().clone();
        if let Some(id) = held {
            let (q, r) = (queue.clone(), runner_id.clone());
            let res = tokio::task::spawn_blocking(move || q.heartbeat(&id, &r, lease)).await;
            if let Ok(Err(e)) = res {
                eprintln!("toto: heartbeat failed: {e}");
            }
        }
    }
}
