//! Credential proxy: lets an agent inside the sandbox use a model API without ever holding the
//! credential (ADR 12).
//!
//! The proxy listens on a unix socket that is bind-mounted into the container (which keeps
//! `--network none`; a relay inside the container exposes it as a loopback port). It accepts only
//! the Messages API calls an agent needs, **replaces any credentials the client sent with the real
//! one**, forwards upstream, streams the response back, and counts the tokens in what comes back,
//! so metering does not depend on anything the agent reports.

use crate::{Error, Result};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How the proxy authenticates upstream. The secret never leaves the proxy process.
pub enum Auth {
    /// `Authorization: Bearer <token>`; with `oauth` the `oauth-2025-04-20` beta flag is added,
    /// which subscription (claude.ai) tokens need.
    Bearer { token: String, oauth: bool },
    /// `x-api-key: <key>`.
    ApiKey(String),
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Auth::Bearer { oauth: true, .. } => "Auth::Bearer(oauth, <redacted>)",
            Auth::Bearer { .. } => "Auth::Bearer(<redacted>)",
            Auth::ApiKey(_) => "Auth::ApiKey(<redacted>)",
        })
    }
}

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 16;
const OAUTH_BETA: &str = "oauth-2025-04-20";

/// Request headers never forwarded: credentials the client might send, and hop-by-hop headers.
const DROP: [&str; 12] = [
    "authorization", "x-api-key", "cookie", "proxy-authorization", "host", "connection", "content-length", "transfer-encoding", "accept-encoding", "keep-alive", "upgrade", "te",
];

struct Shared {
    upstream: String,
    auth: Auth,
    tokens: AtomicU64,
    requests: AtomicU64,
    active: AtomicU64,
    stop: AtomicBool,
}

pub struct AuthProxy {
    shared: Arc<Shared>,
    socket: PathBuf,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl AuthProxy {
    /// Starts serving on `socket` (its parent directory should be private to the runner user).
    /// `upstream` is the API origin, e.g. `https://api.anthropic.com`.
    pub fn start(socket: &Path, upstream: &str, auth: Auth) -> Result<Self> {
        let _ = std::fs::remove_file(socket);
        let listener = UnixListener::bind(socket)?;
        // The container user must be able to connect through the bind mount; the private parent
        // directory keeps other host users out.
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666))?;
        let shared = Arc::new(Shared { upstream: upstream.trim_end_matches('/').to_string(), auth, tokens: 0.into(), requests: 0.into(), active: 0.into(), stop: false.into() });
        let s = shared.clone();
        let thread = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if s.stop.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(conn) = conn else { continue };
                if s.active.load(Ordering::Relaxed) >= MAX_CONNECTIONS as u64 {
                    let _ = respond_error(&conn, 503, "too many connections");
                    continue;
                }
                s.active.fetch_add(1, Ordering::Relaxed);
                let s2 = s.clone();
                std::thread::spawn(move || {
                    let _ = handle(&s2, conn);
                    s2.active.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });
        Ok(Self { shared, socket: socket.to_path_buf(), thread: Some(thread) })
    }

    /// Tokens counted from upstream responses so far: input + cache creation + output.
    pub fn tokens(&self) -> u64 {
        self.shared.tokens.load(Ordering::Relaxed)
    }

    pub fn requests(&self) -> u64 {
        self.shared.requests.load(Ordering::Relaxed)
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        let _ = UnixStream::connect(&self.socket); // wake the accept loop
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

impl Drop for AuthProxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn respond_error(mut conn: &UnixStream, status: u16, msg: &str) -> std::io::Result<()> {
    let body = format!(r#"{{"type":"error","error":{{"type":"toto_proxy_error","message":"{msg}"}}}}"#);
    write!(conn, "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", reason(status), body.len())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        413 => "Payload Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Only what an agent needs to talk to the Messages API.
fn allowed(method: &str, path: &str) -> bool {
    matches!((method, path), ("POST", "/v1/messages") | ("POST", "/v1/messages/count_tokens"))
}

fn handle(sh: &Shared, conn: UnixStream) -> std::io::Result<()> {
    conn.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut reader = BufReader::new(&conn);
    // request line and headers
    let mut head = String::new();
    loop {
        let mut line = String::new();
        let n = reader.by_ref().take(MAX_HEADER_BYTES as u64).read_line(&mut line)?;
        if n == 0 || head.len() + line.len() > MAX_HEADER_BYTES {
            return respond_error(&conn, 400, "bad request head");
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        head.push_str(&line);
    }
    let mut lines = head.lines();
    let mut parts = lines.next().unwrap_or("").split_whitespace();
    let (method, target) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
    let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))).collect();
    let (path, query) = target.split_once('?').map_or((target.as_str(), ""), |(p, q)| (p, q));

    // Connectivity check some clients make against the base URL: answered locally, never forwarded.
    if (method == "HEAD" || method == "GET") && path == "/api/hello" {
        return write!(&conn, "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    }
    if !allowed(&method, path) {
        return respond_error(&conn, 403, "this proxy only forwards POST /v1/messages");
    }
    if headers.iter().any(|(k, v)| k == "transfer-encoding" && !v.eq_ignore_ascii_case("identity")) {
        return respond_error(&conn, 400, "chunked request bodies are not supported");
    }
    let len: u64 = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    if len > MAX_BODY_BYTES {
        return respond_error(&conn, 413, "request body too large");
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;

    sh.requests.fetch_add(1, Ordering::Relaxed);
    match forward(sh, &method, path, query, &headers, body, &conn) {
        Ok(()) => Ok(()),
        Err(e) => respond_error(&conn, 502, &format!("upstream error: {}", e.to_string().replace(['"', '\\'], "'"))),
    }
}

fn forward(sh: &Shared, method: &str, path: &str, query: &str, headers: &[(String, String)], body: Vec<u8>, conn: &UnixStream) -> Result<()> {
    let url = if query.is_empty() { format!("{}{path}", sh.upstream) } else { format!("{}{path}?{query}", sh.upstream) };
    let mut req = ureq::http::Request::builder().method(method).uri(&url);
    let mut beta: Vec<String> = Vec::new();
    for (k, v) in headers {
        if DROP.contains(&k.as_str()) {
            continue;
        }
        if k == "anthropic-beta" {
            beta.extend(v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
            continue;
        }
        req = req.header(k.as_str(), v.as_str());
    }
    match &sh.auth {
        Auth::Bearer { token, oauth } => {
            req = req.header("authorization", format!("Bearer {token}"));
            if *oauth && !beta.iter().any(|b| b == OAUTH_BETA) {
                beta.push(OAUTH_BETA.into());
            }
        }
        Auth::ApiKey(key) => req = req.header("x-api-key", key.as_str()),
    }
    if !beta.is_empty() {
        req = req.header("anthropic-beta", beta.join(","));
    }
    let req = req.header("accept-encoding", "identity").body(body).map_err(|e| Error::Harness(e.to_string()))?;

    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(900))).build().into();
    let resp = agent.run(req).map_err(|e| Error::Harness(e.to_string()))?;
    let (parts, body) = resp.into_parts();
    let status = parts.status.as_u16();
    let sse = parts.headers.get("content-type").and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("text/event-stream"));

    let mut out = conn;
    write!(out, "HTTP/1.1 {status} {}\r\n", parts.status.canonical_reason().unwrap_or("Status"))?;
    for (k, v) in &parts.headers {
        let name = k.as_str();
        if matches!(name, "connection" | "transfer-encoding" | "content-encoding" | "keep-alive" | "set-cookie") {
            continue;
        }
        if let Ok(v) = v.to_str() {
            write!(out, "{name}: {v}\r\n")?;
        }
    }
    write!(out, "connection: close\r\n\r\n")?; // the body is delimited by closing the connection (or content-length)

    let mut scanner = UsageScanner::default();
    let (mut reader, mut buf) = (body.into_reader(), [0u8; 8192]);
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        scanner.feed(&buf[..n], sse);
        out.write_all(&buf[..n])?;
        out.flush()?;
    }
    sh.tokens.fetch_add(scanner.total(), Ordering::Relaxed);
    Ok(())
}

/// Counts tokens in a Messages API response, streamed (SSE) or not.
#[derive(Default)]
pub struct UsageScanner {
    line: Vec<u8>,
    json_body: Vec<u8>,
    input: u64,
    cache_creation: u64,
    output: u64,
}

impl UsageScanner {
    pub fn feed(&mut self, bytes: &[u8], sse: bool) {
        if !sse {
            if self.json_body.len() < 16 * 1024 * 1024 {
                self.json_body.extend_from_slice(bytes);
            }
            return;
        }
        for &b in bytes {
            if b == b'\n' {
                self.sse_line();
                self.line.clear();
            } else if self.line.len() < 1024 * 1024 {
                self.line.push(b);
            }
        }
    }

    fn sse_line(&mut self) {
        let Some(data) = self.line.strip_prefix(b"data:") else { return };
        let Ok(v) = serde_json::from_slice::<Value>(data.trim_ascii()) else { return };
        match v["type"].as_str() {
            Some("message_start") => self.take(&v["message"]["usage"], true),
            Some("message_delta") => self.take(&v["usage"], false),
            _ => {}
        }
    }

    /// `message_start` carries input and cache figures; `message_delta` carries the running
    /// output total, so the latest value wins.
    fn take(&mut self, u: &Value, start: bool) {
        let n = |k: &str| u[k].as_u64();
        if start {
            self.input = n("input_tokens").unwrap_or(0);
            self.cache_creation = n("cache_creation_input_tokens").unwrap_or(0);
        }
        if let Some(o) = n("output_tokens") {
            self.output = o;
        }
        if let Some(i) = n("input_tokens").filter(|_| !start) {
            self.input = i; // some responses restate input in message_delta
        }
    }

    pub fn total(&mut self) -> u64 {
        if !self.json_body.is_empty() {
            if let Ok(v) = serde_json::from_slice::<Value>(&self.json_body) {
                let u = &v["usage"];
                let n = |k: &str| u[k].as_u64().unwrap_or(0);
                self.input = n("input_tokens");
                self.cache_creation = n("cache_creation_input_tokens");
                self.output = n("output_tokens");
            }
        }
        self.input + self.cache_creation + self.output
    }
}
