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

/// Snapshot written to `<state_dir>/status.json` for `toto status` and the local UI.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Status {
    pub state: String,
    pub task: Option<String>,
    pub ticks: u64,
    pub submitted: u64,
    pub dropped: u64,
    pub last_error: Option<String>,
    /// Set while the runner pauses for quota (`state` is `paused`).
    #[serde(default)]
    pub paused_until: Option<String>,
    #[serde(default)]
    pub pause_reason: Option<String>,
    /// The contributor paused the runner (`toto pause`, or the page); `state` is `paused`.
    #[serde(default)]
    pub user_paused: bool,
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

/// Runs until `shutdown` resolves. Fails fast if the configured sandbox does not work. With
/// `config_path` and `ui_addr` set, also serves the local page and API from this process.
pub async fn run(cfg: Config, config_path: Option<std::path::PathBuf>, shutdown: impl Future<Output = ()>) -> Result<()> {
    let runner = cfg.build()?;
    runner.sandbox.probe()?;
    runner.harness.probe()?;
    let ui = match (&cfg.ui_addr, config_path) {
        (Some(addr), Some(path)) => match crate::ui::bind(path, &cfg.state_dir, addr).await {
            Ok((listener, state, url)) => {
                println!("local page: {url}");
                Some(tokio::spawn(async move {
                    let _ = axum::serve(listener, crate::ui::router(state)).await;
                }))
            }
            Err(e) => {
                eprintln!("the local page is not served: {e}");
                None
            }
        },
        _ => None,
    };
    let out = run_runner(runner, cfg, shutdown).await;
    if let Some(ui) = ui {
        ui.abort();
    }
    out
}

/// Sleeps `wait`, waking early when the contributor's pause marker appears or disappears.
async fn wait_or_control(state_dir: &Path, wait: Duration) {
    let was = crate::control::is_paused(state_dir);
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return;
        }
        tokio::time::sleep(left.min(Duration::from_secs(2))).await;
        if crate::control::is_paused(state_dir) != was {
            return;
        }
    }
}

async fn run_runner(runner: DaemonRunner, cfg: Config, shutdown: impl Future<Output = ()>) -> Result<()> {
    tokio::pin!(shutdown);
    let (queue, runner_id, lease, current) = (runner.queue.clone(), runner.runner_id(), runner.lease, runner.current_lease.clone());
    let heartbeat = tokio::spawn(heartbeat_loop(queue.clone(), runner_id.clone(), lease, current.clone()));
    let runner = Arc::new(Mutex::new(runner));
    let (poll, mut status, mut backoff) = (Duration::from_secs(cfg.poll_secs.max(1)), Status::default(), Duration::ZERO);
    status.write(&cfg.state_dir, "idle", None);

    'main: loop {
        // The contributor's pause comes before anything else: no task is taken while it holds.
        if crate::control::is_paused(&cfg.state_dir) {
            status.user_paused = true;
            status.pause_reason = Some("paused by you".into());
            status.paused_until = None;
            status.write(&cfg.state_dir, "paused", None);
            tokio::select! {
                _ = wait_or_control(&cfg.state_dir, Duration::from_secs(3600)) => continue 'main,
                _ = &mut shutdown => break 'main,
            }
        }
        status.user_paused = false;
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
                status.paused_until = None;
                status.pause_reason = None;
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
                status.paused_until = None;
                status.pause_reason = None;
                status.write(&cfg.state_dir, "idle", None);
                poll
            }
            Ok(Tick::Paused { until, reason }) => {
                backoff = Duration::ZERO;
                status.paused_until = Some(until.to_rfc3339());
                status.pause_reason = Some(reason);
                status.write(&cfg.state_dir, "paused", None);
                // Re-check at the reset, and at least every few minutes in case the signal changes.
                (until - Local::now()).to_std().unwrap_or(poll).clamp(poll, MAX_BACKOFF)
            }
            Err(e) => {
                backoff = (backoff * 2).clamp(poll, MAX_BACKOFF);
                status.last_error = Some(e.to_string());
                status.write(&cfg.state_dir, "backoff", None);
                backoff
            }
        };
        tokio::select! {
            _ = wait_or_control(&cfg.state_dir, wait) => {}
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
