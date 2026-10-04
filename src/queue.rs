//! Queue client (ADR 1: runners pull leases; ADR 8: an open protocol, many endpoints).

use crate::manifest::TaskManifest;
use crate::result::TaskResult;
use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub trait QueueClient: Send + Sync {
    /// Tasks currently claimable. The runner picks locally so consent stays on the machine.
    fn available(&self) -> Result<Vec<TaskManifest>>;
    fn claim(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()>;
    fn heartbeat(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()>;
    /// Idempotent per (task, runner): resubmitting the same result is not an error.
    fn submit(&self, result: &TaskResult) -> Result<()>;
    /// The input bundle with this SHA-256 (hex), if the queue has it.
    fn bundle(&self, hash: &str) -> Result<Option<Vec<u8>>>;
    /// Gives a lease back without a result (rejected or aborted tasks).
    fn release(&self, task_id: &str, runner_id: &str) -> Result<()>;
}

impl<T: QueueClient + ?Sized> QueueClient for std::sync::Arc<T> {
    fn available(&self) -> Result<Vec<TaskManifest>> {
        (**self).available()
    }
    fn claim(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        (**self).claim(task_id, runner_id, lease)
    }
    fn heartbeat(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        (**self).heartbeat(task_id, runner_id, lease)
    }
    fn submit(&self, result: &TaskResult) -> Result<()> {
        (**self).submit(result)
    }
    fn release(&self, task_id: &str, runner_id: &str) -> Result<()> {
        (**self).release(task_id, runner_id)
    }
    fn bundle(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        (**self).bundle(hash)
    }
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
    bundles: HashMap<String, Vec<u8>>,
}

impl InMemoryQueue {
    pub fn post(&self, t: TaskManifest) {
        self.state.lock().unwrap().tasks.push(t);
    }

    /// Stores an input bundle and returns its hash for the manifest's `inputs`.
    pub fn post_bundle(&self, bytes: Vec<u8>) -> String {
        let h = crate::archive::sha256_hex(&bytes);
        self.state.lock().unwrap().bundles.insert(h.clone(), bytes);
        h
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

    fn bundle(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.state.lock().unwrap().bundles.get(hash).cloned())
    }
}

/// File-spool queue: a directory the daemon polls. Lets the daemon run end to end before the
/// HTTP coordinator exists, and doubles as an offline queue for trusted pilots.
///
/// Layout: `tasks/<id>.json` (signed manifests), `leases/<id>` (`runner\nexpiry_unix`),
/// `results/<id>.<runner>.json`. Claiming is atomic via `create_new`; stealing an *expired*
/// lease has a small race that the real coordinator does not have.
pub struct DirQueue {
    root: std::path::PathBuf,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn valid_id(id: &str) -> Result<()> {
    if !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        Ok(())
    } else {
        Err(Error::Queue(format!("invalid task id `{id}`")))
    }
}

impl DirQueue {
    pub fn new(root: impl Into<std::path::PathBuf>) -> Result<Self> {
        let root = root.into();
        for d in ["tasks", "leases", "results", "bundles"] {
            std::fs::create_dir_all(root.join(d))?;
        }
        Ok(Self { root })
    }

    pub fn post(&self, t: &TaskManifest) -> Result<()> {
        valid_id(&t.id)?;
        write_atomic(&self.root.join("tasks").join(format!("{}.json", t.id)), &serde_json::to_vec_pretty(t)?)
    }

    /// Stores an input bundle as `bundles/<sha256>` and returns the hash.
    pub fn post_bundle(&self, bytes: &[u8]) -> Result<String> {
        let h = crate::archive::sha256_hex(bytes);
        write_atomic(&self.root.join("bundles").join(&h), bytes)?;
        Ok(h)
    }

    pub fn results(&self) -> Result<Vec<TaskResult>> {
        let mut out = vec![];
        for e in std::fs::read_dir(self.root.join("results"))? {
            if let Ok(r) = serde_json::from_slice(&std::fs::read(e?.path())?) {
                out.push(r);
            }
        }
        Ok(out)
    }

    fn lease_path(&self, id: &str) -> std::path::PathBuf {
        self.root.join("leases").join(id)
    }

    fn read_lease(&self, id: &str) -> Option<(String, u64)> {
        let s = std::fs::read_to_string(self.lease_path(id)).ok()?;
        let (runner, exp) = s.split_once('\n')?;
        Some((runner.to_string(), exp.trim().parse().ok()?))
    }

    fn has_result(&self, id: &str) -> bool {
        std::fs::read_dir(self.root.join("results"))
            .map(|d| d.flatten().any(|e| e.file_name().to_string_lossy().starts_with(&format!("{id}."))))
            .unwrap_or(false)
    }
}

fn write_atomic(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

impl QueueClient for DirQueue {
    fn available(&self) -> Result<Vec<TaskManifest>> {
        let mut out = vec![];
        for e in std::fs::read_dir(self.root.join("tasks"))? {
            let path = e?.path();
            if path.extension().is_none_or(|x| x != "json") {
                continue;
            }
            let Ok(t) = serde_json::from_slice::<TaskManifest>(&std::fs::read(&path)?) else { continue };
            let leased = self.read_lease(&t.id).is_some_and(|(_, exp)| exp > now_unix());
            if valid_id(&t.id).is_ok() && !leased && !self.has_result(&t.id) {
                out.push(t);
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    fn claim(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        use std::io::Write;
        valid_id(task_id)?;
        let body = format!("{runner_id}\n{}", now_unix() + lease.as_secs());
        let path = self.lease_path(task_id);
        for _ in 0..2 {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut f) => {
                    f.write_all(body.as_bytes())?;
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match self.read_lease(task_id) {
                    Some((holder, exp)) if exp > now_unix() && holder != runner_id => return Err(Error::Queue("already leased".into())),
                    Some((holder, _)) if holder == runner_id => return write_atomic(&path, body.as_bytes()),
                    _ => {
                        let _ = std::fs::remove_file(&path); // expired or corrupt: take it over
                    }
                },
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::Queue("could not claim".into()))
    }

    fn heartbeat(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        valid_id(task_id)?;
        match self.read_lease(task_id) {
            Some((holder, exp)) if holder == runner_id && exp > now_unix() => {
                write_atomic(&self.lease_path(task_id), format!("{runner_id}\n{}", now_unix() + lease.as_secs()).as_bytes())
            }
            _ => Err(Error::Queue("lease lost".into())),
        }
    }

    fn submit(&self, result: &TaskResult) -> Result<()> {
        result.verify()?;
        valid_id(&result.task_id)?;
        let name = format!("{}.{}.json", result.task_id, &result.runner_id[..16]);
        write_atomic(&self.root.join("results").join(name), &serde_json::to_vec_pretty(result)?)
    }

    fn release(&self, task_id: &str, runner_id: &str) -> Result<()> {
        valid_id(task_id)?;
        if self.read_lease(task_id).is_some_and(|(h, _)| h == runner_id) {
            let _ = std::fs::remove_file(self.lease_path(task_id));
        }
        Ok(())
    }

    fn bundle(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Queue(format!("invalid bundle hash `{hash}`")));
        }
        match std::fs::read(self.root.join("bundles").join(hash)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
