//! The queue protocol over HTTP (see `docs/queue-protocol.md`): a client (`HttpQueue`), a client that
//! spans several coordinators (`MultiQueue`, ADR 8) and a small reference server over a `DirQueue`
//! (`toto serve-queue`) for pilots and tests.
//!
//! The server is a convenience, not a trust anchor: runners verify project signatures and the
//! result envelope themselves, so nothing here can forge a task or a result.

use crate::dsse::Envelope;
use crate::manifest::peek_manifest;
use crate::queue::{DirQueue, QueueClient};
use crate::result::SignedResult;
use crate::{Error, Result};
use serde_json::json;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_JSON: u64 = 1 << 20;
const MAX_BODY: u64 = 256 << 20;

fn qerr(e: impl std::fmt::Display) -> Error {
    Error::Queue(e.to_string())
}

// ---------------------------------------------------------------------------------------- client

pub struct HttpQueue {
    base: String,
    token: Option<String>,
    agent: ureq::Agent,
}

impl HttpQueue {
    pub fn new(base: &str, token: Option<String>) -> Self {
        let agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(60))).build().into();
        Self { base: base.trim_end_matches('/').to_string(), token, agent }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Sends a request; returns the status and body. 404 and 409 are data, other failures errors.
    fn call(&self, method: &str, path: &str, body: Option<Vec<u8>>, ctype: &str) -> Result<(u16, Vec<u8>)> {
        let mut req = ureq::http::Request::builder().method(method).uri(self.url(path));
        if let Some(t) = &self.token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let req = req.header("content-type", ctype).body(body.unwrap_or_default()).map_err(qerr)?;
        let mut resp = self.agent.run(req).map_err(|e| qerr(format!("{} {path}: {e}", self.base)))?;
        let status = resp.status().as_u16();
        let bytes = resp.body_mut().with_config().limit(MAX_BODY).read_to_vec().map_err(qerr)?;
        match status {
            200..=299 | 404 | 409 => Ok((status, bytes)),
            _ => Err(qerr(format!("{} {path}: HTTP {status}: {}", self.base, String::from_utf8_lossy(&bytes).chars().take(200).collect::<String>()))),
        }
    }

    fn lease_call(&self, action: &str, task_id: &str, runner_id: &str, lease: Option<Duration>) -> Result<()> {
        let mut body = json!({"runner_id": runner_id});
        if let Some(l) = lease {
            body["lease_secs"] = l.as_secs().into();
        }
        let (status, bytes) = self.call("POST", &format!("/v1/tasks/{task_id}/{action}"), Some(serde_json::to_vec(&body)?), "application/json")?;
        match status {
            409 | 404 => Err(qerr(String::from_utf8_lossy(&bytes).trim().to_string())),
            _ => Ok(()),
        }
    }
}

impl QueueClient for HttpQueue {
    fn available(&self) -> Result<Vec<Envelope>> {
        let (_, body) = self.call("GET", "/v1/tasks", None, "application/json")?;
        Ok(serde_json::from_slice(&body)?)
    }
    fn claim(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        self.lease_call("claim", task_id, runner_id, Some(lease))
    }
    fn heartbeat(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        self.lease_call("heartbeat", task_id, runner_id, Some(lease))
    }
    fn release(&self, task_id: &str, runner_id: &str) -> Result<()> {
        self.lease_call("release", task_id, runner_id, None)
    }
    fn submit(&self, result: &SignedResult) -> Result<()> {
        let (status, body) = self.call("PUT", "/v1/results", Some(serde_json::to_vec(result)?), "application/json")?;
        if status == 409 || status == 404 {
            return Err(qerr(String::from_utf8_lossy(&body).trim().to_string()));
        }
        Ok(())
    }
    fn bundle(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(qerr(format!("invalid bundle hash `{hash}`")));
        }
        let (status, body) = self.call("GET", &format!("/v1/bundles/{hash}"), None, "application/octet-stream")?;
        Ok((status != 404).then_some(body))
    }
}

// ------------------------------------------------------------------------------------ many queues

/// Several coordinators behind one `QueueClient`. Tasks remember where they came from, so claims,
/// heartbeats and results go back to that endpoint. A coordinator that is down is skipped.
pub struct MultiQueue {
    endpoints: Vec<Arc<dyn QueueClient>>,
    origin: Mutex<HashMap<String, usize>>,
}

impl MultiQueue {
    pub fn new(endpoints: Vec<Arc<dyn QueueClient>>) -> Self {
        Self { endpoints, origin: Default::default() }
    }

    fn home(&self, task_id: &str) -> Result<&Arc<dyn QueueClient>> {
        let i = *self.origin.lock().unwrap().get(task_id).ok_or_else(|| qerr(format!("task `{task_id}` was not seen on any coordinator")))?;
        Ok(&self.endpoints[i])
    }
}

impl QueueClient for MultiQueue {
    fn available(&self) -> Result<Vec<Envelope>> {
        let (mut all, mut last_err, mut ok) = (vec![], None, false);
        for (i, q) in self.endpoints.iter().enumerate() {
            match q.available() {
                Ok(tasks) => {
                    ok = true;
                    let mut origin = self.origin.lock().unwrap();
                    for t in tasks {
                        if let Ok(m) = peek_manifest(&t) {
                            origin.entry(m.id).or_insert(i);
                        }
                        all.push(t);
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }
        match (ok, last_err) {
            (false, Some(e)) => Err(e),
            _ => Ok(all),
        }
    }
    fn claim(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        self.home(task_id)?.claim(task_id, runner_id, lease)
    }
    fn heartbeat(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        self.home(task_id)?.heartbeat(task_id, runner_id, lease)
    }
    fn release(&self, task_id: &str, runner_id: &str) -> Result<()> {
        self.home(task_id)?.release(task_id, runner_id)
    }
    fn submit(&self, result: &SignedResult) -> Result<()> {
        let id = result.open()?.task_id;
        self.home(&id)?.submit(result)
    }
    fn bundle(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        // Bundles are addressed by hash and the runner checks the hash, so any endpoint may answer.
        for q in &self.endpoints {
            if let Ok(Some(b)) = q.bundle(hash) {
                return Ok(Some(b));
            }
        }
        Ok(None)
    }
}

// ------------------------------------------------------------------------------------ the server

pub struct Server {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Serves `queue` on `addr` (use port 0 to pick one). With a `token`, every request needs
/// `Authorization: Bearer <token>`.
pub fn serve(queue: Arc<DirQueue>, addr: &str, token: Option<String>) -> Result<Server> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let local = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let thread = std::thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((s, _)) => {
                    let (q, t) = (queue.clone(), token.clone());
                    std::thread::spawn(move || {
                        let _ = handle(s, &q, t.as_deref());
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    });
    Ok(Server { addr: local, stop, thread: Some(thread) })
}

fn respond(s: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        _ => "Error",
    };
    write!(s, "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
    s.write_all(body)
}

fn err_body(msg: impl std::fmt::Display) -> Vec<u8> {
    json!({"error": msg.to_string()}).to_string().into_bytes()
}

fn handle(mut s: TcpStream, q: &DirQueue, token: Option<&str>) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut r = BufReader::new(s.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let (method, path) = {
        let mut p = line.split_whitespace();
        (p.next().unwrap_or("").to_string(), p.next().unwrap_or("").to_string())
    };
    let (mut len, mut auth) = (0u64, None);
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => len = v.trim().parse().unwrap_or(0),
                "authorization" => auth = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    if token.is_some_and(|t| auth.as_deref() != Some(&format!("Bearer {t}"))) {
        return respond(&mut s, 401, "application/json", &err_body("missing or wrong token"));
    }
    if len > MAX_BODY {
        return respond(&mut s, 413, "application/json", &err_body("body too large"));
    }
    let mut body = vec![];
    r.take(len).read_to_end(&mut body)?;
    let (status, ctype, out) = route(q, &method, &path, &body);
    respond(&mut s, status, ctype, &out)
}

fn route(q: &DirQueue, method: &str, path: &str, body: &[u8]) -> (u16, &'static str, Vec<u8>) {
    const J: &str = "application/json";
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let lease = |v: &serde_json::Value| Duration::from_secs(v["lease_secs"].as_u64().unwrap_or(0).clamp(1, 24 * 3600));
    let parse = |max: u64| -> Option<serde_json::Value> { (body.len() as u64 <= max).then(|| serde_json::from_slice(body).ok()).flatten() };
    let done = |r: Result<()>| match r {
        Ok(()) => (204, J, vec![]),
        Err(e) => (409, J, err_body(e)),
    };
    match (method, parts.as_slice()) {
        ("GET", ["v1", "tasks"]) => match q.available().and_then(|t| Ok(serde_json::to_vec(&t)?)) {
            Ok(b) => (200, J, b),
            Err(e) => (500, J, err_body(e)),
        },
        ("POST", ["v1", "tasks", id, action @ ("claim" | "heartbeat" | "release")]) => {
            let Some(v) = parse(MAX_JSON) else { return (400, J, err_body("bad json")) };
            let Some(runner) = v["runner_id"].as_str() else { return (400, J, err_body("runner_id missing")) };
            match *action {
                "claim" => done(q.claim(id, runner, lease(&v))),
                "heartbeat" => done(q.heartbeat(id, runner, lease(&v))),
                _ => done(q.release(id, runner)),
            }
        }
        ("PUT", ["v1", "results"]) => match serde_json::from_slice::<SignedResult>(body) {
            Ok(r) => done(q.submit(&r)),
            Err(e) => (400, J, err_body(e)),
        },
        ("GET", ["v1", "bundles", hash]) => match q.bundle(hash) {
            Ok(Some(b)) => (200, "application/octet-stream", b),
            Ok(None) => (404, J, err_body("no such bundle")),
            Err(e) => (400, J, err_body(e)),
        },
        _ => (404, J, err_body("no such route")),
    }
}
