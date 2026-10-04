//! `togra-mcp-exec`: a minimal MCP server (stdio, newline-delimited JSON-RPC) that gives the
//! agent shell and file tools. It runs *inside* the task container, started by the runner as
//! `docker exec -i <container> /togra/mcp-exec`, so every tool call executes in the sandbox
//! and the agent loop with its login stays outside (ADR 10).
//!
//! Build static for any Linux image: `cargo build --release --target x86_64-unknown-linux-musl
//! --bin togra-mcp-exec`.

use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_OUT: usize = 64 * 1024;
const MAX_READ: u64 = 256 * 1024;

fn tools() -> Value {
    let obj = |props: Value, req: &[&str]| json!({"type": "object", "properties": props, "required": req});
    json!([
        {"name": "run_command", "description": "Run a shell command (sh -c) in the task environment and return its output.",
         "inputSchema": obj(json!({"command": {"type": "string"}, "cwd": {"type": "string"}, "timeout_secs": {"type": "integer"}}), &["command"])},
        {"name": "read_file", "description": "Read a UTF-8 text file (up to 256 KiB).",
         "inputSchema": obj(json!({"path": {"type": "string"}}), &["path"])},
        {"name": "write_file", "description": "Write a text file, creating parent directories.",
         "inputSchema": obj(json!({"path": {"type": "string"}, "content": {"type": "string"}}), &["path", "content"])},
        {"name": "list_dir", "description": "List a directory.",
         "inputSchema": obj(json!({"path": {"type": "string"}}), &["path"])},
    ])
}

fn clip(mut b: Vec<u8>) -> String {
    let cut = b.len() > MAX_OUT;
    b.truncate(MAX_OUT);
    let mut s = String::from_utf8_lossy(&b).into_owned();
    if cut {
        s.push_str("\n[output truncated]");
    }
    s
}

fn run_command(a: &Value) -> Result<String, String> {
    let cmd = a["command"].as_str().ok_or("`command` must be a string")?;
    let secs = a["timeout_secs"].as_u64().unwrap_or(120).clamp(1, 600);
    let mut c = Command::new("sh");
    c.args(["-c", cmd]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(d) = a["cwd"].as_str() {
        c.current_dir(d);
    }
    let mut child = c.spawn().map_err(|e| format!("cannot start sh: {e}"))?;
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let drain = |r: &mut dyn Read| {
        let mut b = Vec::new();
        let _ = r.take(MAX_OUT as u64 + 1).read_to_end(&mut b);
        b
    };
    let (t_out, t_err) = (std::thread::spawn(move || drain(&mut so)), std::thread::spawn(move || drain(&mut se)));
    let deadline = Instant::now() + Duration::from_secs(secs);
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break Some(s);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (out, err) = (clip(t_out.join().unwrap_or_default()), clip(t_err.join().unwrap_or_default()));
    let head = match status {
        Some(s) => format!("exit: {}", s.code().map_or("signal".into(), |c| c.to_string())),
        None => format!("exit: timed out after {secs}s"),
    };
    Ok(format!("{head}\n--- stdout ---\n{out}\n--- stderr ---\n{err}"))
}

fn call(name: &str, a: &Value) -> Result<String, String> {
    let path = || a["path"].as_str().ok_or_else(|| "`path` must be a string".to_string());
    match name {
        "run_command" => run_command(a),
        "read_file" => {
            let p = path()?;
            let len = std::fs::metadata(p).map_err(|e| format!("{p}: {e}"))?.len();
            if len > MAX_READ {
                return Err(format!("{p}: {len} bytes exceeds {MAX_READ}"));
            }
            std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))
        }
        "write_file" => {
            let (p, c) = (path()?, a["content"].as_str().ok_or("`content` must be a string")?);
            if let Some(parent) = std::path::Path::new(p).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(p, c).map(|_| format!("wrote {} bytes to {p}", c.len())).map_err(|e| format!("{p}: {e}"))
        }
        "list_dir" => {
            let p = path()?;
            let mut names: Vec<String> = std::fs::read_dir(p)
                .map_err(|e| format!("{p}: {e}"))?
                .flatten()
                .map(|e| format!("{}{}", e.file_name().to_string_lossy(), if e.path().is_dir() { "/" } else { "" }))
                .collect();
            names.sort();
            Ok(names.join("\n"))
        }
        other => Err(format!("unknown tool `{other}`")),
    }
}

fn handle(req: &Value) -> Option<Value> {
    let id = req.get("id")?.clone(); // notifications have no id and get no reply
    let reply = |r: Result<Value, (i64, String)>| match r {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
    };
    Some(reply(match req["method"].as_str().unwrap_or("") {
        "initialize" => Ok(json!({
            "protocolVersion": req["params"]["protocolVersion"].as_str().unwrap_or("2024-11-05"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "togra-exec", "version": env!("CARGO_PKG_VERSION")},
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => {
            let p = &req["params"];
            let out = call(p["name"].as_str().unwrap_or(""), &p["arguments"]);
            let (text, is_err) = match out {
                Ok(t) => (t, false),
                Err(e) => (e, true),
            };
            Ok(json!({"content": [{"type": "text", "text": text}], "isError": is_err}))
        }
        m => Err((-32601, format!("method not found: {m}"))),
    }))
}

fn main() {
    let (stdin, mut stdout) = (std::io::stdin(), std::io::stdout());
    for line in stdin.lock().lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(req) => handle(&req),
            Err(e) => Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}})),
        };
        if let Some(r) = resp {
            let _ = writeln!(stdout, "{r}");
            let _ = stdout.flush();
        }
    }
}
