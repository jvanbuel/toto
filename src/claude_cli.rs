//! `ClaudeCliHarness`: runs a task with the official `claude` CLI, authenticated by the
//! contributor's own Claude subscription (ADR 11).
//!
//! The agent loop and the login stay on the host. The CLI is started with every built-in tool
//! turned off and exactly one MCP server, `sandbox`, whose command is
//! `docker exec -i <container> /togra/mcp-exec`, so everything the agent does to files or
//! processes happens inside the hardened container (ADR 10). The CLI runs from a scratch
//! directory holding only the task's skills, with a dedicated config dir and a cleared
//! environment, so the contributor's own settings, memory, hooks, MCP servers and skills never
//! reach a task, and no API key in the environment can change who is billed.
//!
//! Subscription auth uses a long-lived token from `claude setup-token`, stored by `togra login`
//! with mode 0600 and passed to the CLI process only. Never use `--bare`: it ignores
//! subscription login.

use crate::harness::Harness;
use crate::manifest::{TaskContext, TaskManifest};
use crate::meter::UsageMeter;
use crate::sandbox::Workspace;
use crate::{Error, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct ClaudeCliHarness {
    pub bin: String,
    /// File holding the `claude setup-token` token (mode 0600).
    pub token_file: PathBuf,
    /// Dedicated `CLAUDE_CONFIG_DIR` and `HOME` base, separate from the contributor's own.
    pub home_dir: PathBuf,
    /// Per-task scratch directories live under here and are removed after each run.
    pub runs_dir: PathBuf,
    pub model: Option<String>,
    pub max_turns: u32,
}

impl ClaudeCliHarness {
    pub fn new(state_dir: &Path, token_file: PathBuf) -> Result<Self> {
        let (home_dir, runs_dir) = (state_dir.join("claude-home"), state_dir.join("runs"));
        std::fs::create_dir_all(&home_dir)?;
        std::fs::create_dir_all(&runs_dir)?;
        Ok(Self { bin: "claude".into(), token_file, home_dir, runs_dir, model: None, max_turns: 40 })
    }

    /// Reads the token, refusing a file that other users can read.
    pub fn read_token(&self) -> Result<String> {
        let meta = std::fs::metadata(&self.token_file).map_err(|e| Error::Harness(format!("no token at {} ({e}); run `togra login`", self.token_file.display())))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Harness(format!("{} is readable by others; chmod 600 it", self.token_file.display())));
        }
        let t = std::fs::read_to_string(&self.token_file)?.trim().to_string();
        if t.is_empty() {
            return Err(Error::Harness("token file is empty; run `togra login`".into()));
        }
        Ok(t)
    }
}

/// Stores a token with mode 0600 (created with that mode, never briefly wider).
pub fn save_token(path: &Path, token: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(token.trim().as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// MCP config for `--mcp-config`: the runner's bridge plus any project URL servers.
pub fn mcp_config(ctx: &TaskContext, bridge: &[String]) -> Value {
    let mut servers = serde_json::Map::new();
    for m in &ctx.mcp_servers {
        let kind = if m.url.split(['?', '#']).next().unwrap_or("").ends_with("/sse") { "sse" } else { "http" };
        servers.insert(m.name.clone(), json!({"type": kind, "url": m.url}));
    }
    // Inserted last so a project server can never replace the runner's own bridge.
    servers.insert(crate::manifest::BRIDGE_SERVER_NAME.into(), json!({"command": bridge[0], "args": &bridge[1..]}));
    json!({"mcpServers": servers})
}

/// Writes the task's skills under `dir/.claude/skills`, the only place the CLI will look.
pub fn write_skills(dir: &Path, ctx: &TaskContext) -> Result<()> {
    for sk in &ctx.skills {
        let sd = dir.join(".claude/skills").join(&sk.name);
        std::fs::create_dir_all(&sd)?;
        let front = format!("---\nname: {}\ndescription: {}\n---\n", sk.name, serde_json::to_string(&sk.description)?);
        std::fs::write(sd.join("SKILL.md"), format!("{front}{}", sk.content))?;
        for (path, text) in &sk.files {
            let target = sd.join(path);
            std::fs::create_dir_all(target.parent().unwrap())?;
            std::fs::write(target, text)?;
        }
    }
    Ok(())
}

/// Environment for the CLI: nothing inherited except what it needs to run and reach the network.
pub fn cli_env(home: &Path, token: &str) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = ["PATH", "LANG", "TZ", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect();
    env.extend([
        ("HOME".into(), home.display().to_string()),
        ("CLAUDE_CONFIG_DIR".into(), home.join(".claude").display().to_string()),
        ("CLAUDE_CODE_OAUTH_TOKEN".into(), token.into()),
        ("DISABLE_AUTOUPDATER".into(), "1".into()),
    ]);
    env
}

fn usage_tokens(u: &Value) -> u64 {
    ["input_tokens", "output_tokens", "cache_creation_input_tokens"].iter().map(|k| u.get(k).and_then(Value::as_u64).unwrap_or(0)).sum()
}

/// Errors the CLI reports on `system/api_retry` that mean the account, not the task, is the problem.
const ACCOUNT_ERRORS: [&str; 5] = ["authentication_failed", "oauth_org_not_allowed", "account_on_hold", "billing_error", "rate_limit"];

impl Harness for ClaudeCliHarness {
    fn probe(&self) -> Result<()> {
        self.read_token()?;
        let out = Command::new(&self.bin).arg("--version").output().map_err(|e| Error::Harness(format!("cannot run `{}`: {e}", self.bin)))?;
        if out.status.success() { Ok(()) } else { Err(Error::Harness("`claude --version` failed".into())) }
    }

    fn supports_context(&self) -> bool {
        true
    }

    fn run(&self, task: &TaskManifest, ws: &Workspace, meter: &mut UsageMeter) -> Result<String> {
        let bridge = ws.bridge_argv().ok_or_else(|| Error::Harness("the claude harness needs a container sandbox with the exec bridge".into()))?;
        task.context.validate()?;
        let token = self.read_token()?;

        let run_dir = self.runs_dir.join(crate::sandbox::DockerSandbox::container_name(&task.id));
        std::fs::create_dir_all(&run_dir)?;
        let _cleanup = RemoveOnDrop(run_dir.clone());
        write_skills(&run_dir, &task.context)?;
        let mcp_path = run_dir.join("mcp.json");
        std::fs::write(&mcp_path, serde_json::to_vec(&mcp_config(&task.context, &bridge))?)?;
        let allowed: Vec<String> = task.context.mcp_servers.iter().map(|m| format!("mcp__{}", m.name)).chain([format!("mcp__{}", crate::manifest::BRIDGE_SERVER_NAME)]).collect();

        let mut cmd = Command::new(&self.bin);
        cmd.args(["-p", "--output-format", "stream-json", "--verbose", "--no-session-persistence"])
            .args(["--tools", ""])
            .args(["--strict-mcp-config", "--mcp-config"]).arg(&mcp_path)
            .args(["--setting-sources", "project", "--permission-mode", "dontAsk", "--permission-prompts", "none"])
            .arg(format!("--allowedTools={}", allowed.join(",")))
            .args(["--max-turns", &self.max_turns.to_string()]);
        if let Some(m) = &self.model {
            cmd.args(["--model", m]);
        }
        let mut child = cmd
            .current_dir(&run_dir)
            .env_clear()
            .envs(cli_env(&self.home_dir, &token))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Harness(format!("cannot run `{}`: {e}", self.bin)))?;

        // The prompt goes over stdin: no argv exposure, no length limit, and variadic flags
        // cannot swallow it.
        child.stdin.take().unwrap().write_all(task.prompt.as_bytes())?;

        let (tx, rx) = mpsc::channel::<String>();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(std::result::Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut stderr = child.stderr.take().unwrap();
        let err_thread = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            s
        });

        let deadline = Instant::now() + Duration::from_secs(task.sandbox_profile.timeout_secs);
        let (mut per_message, mut charged) = (HashMap::<String, u64>::new(), 0u64);
        let (mut result, mut account_error) = (None::<Value>, None::<String>);
        let abort = |child: &mut std::process::Child, e: Error| -> Error {
            let _ = child.kill();
            let _ = child.wait();
            e
        };
        loop {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(line) => {
                    let Ok(ev) = serde_json::from_str::<Value>(&line) else { continue };
                    match (ev["type"].as_str(), ev["subtype"].as_str()) {
                        (Some("system"), Some("init")) => {
                            // Defence in depth: only our MCP tools may exist, and every MCP server must have loaded.
                            let builtin = ev["tools"].as_array().into_iter().flatten().filter_map(Value::as_str).find(|t| !t.starts_with("mcp__"));
                            if let Some(t) = builtin {
                                return Err(abort(&mut child, Error::Harness(format!("built-in tool `{t}` is enabled; refusing to run"))));
                            }
                            if ev["mcp_server_errors"].as_array().is_some_and(|a| !a.is_empty()) {
                                return Err(abort(&mut child, Error::Harness(format!("mcp server config rejected: {}", ev["mcp_server_errors"]))));
                            }
                            let down = ev["mcp_servers"].as_array().into_iter().flatten().find(|s| s["name"] == crate::manifest::BRIDGE_SERVER_NAME && s["status"] != "connected");
                            if let Some(s) = down {
                                return Err(abort(&mut child, Error::Harness(format!("sandbox bridge did not connect: {s}"))));
                            }
                        }
                        (Some("system"), Some("api_retry")) => {
                            if let Some(e) = ev["error"].as_str().filter(|e| ACCOUNT_ERRORS.contains(e)) {
                                account_error = Some(e.to_string());
                            }
                        }
                        (Some("assistant"), _) => {
                            if let (Some(id), usage) = (ev["message"]["id"].as_str(), &ev["message"]["usage"]) {
                                // The same message can appear once per content block: keep the latest figure per id.
                                per_message.insert(id.to_string(), usage_tokens(usage));
                                let total: u64 = per_message.values().sum();
                                if total > charged {
                                    let delta = total - charged;
                                    charged = total;
                                    if let Err(e) = meter.record(delta) {
                                        return Err(abort(&mut child, e));
                                    }
                                }
                            }
                        }
                        (Some("result"), _) => result = Some(ev),
                        _ => {}
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if Instant::now() >= deadline {
                return Err(abort(&mut child, Error::Harness(format!("timed out after {}s", task.sandbox_profile.timeout_secs))));
            }
        }
        let status = child.wait()?;
        let stderr = err_thread.join().unwrap_or_default();

        let Some(res) = result else {
            let why = account_error.map_or_else(|| stderr.lines().last().unwrap_or("no result").to_string(), |e| format!("{e} (account problem)"));
            return Err(Error::Harness(format!("claude exited with {status} and no result: {why}")));
        };
        if let Some(total) = res.get("usage").map(usage_tokens).filter(|t| *t > charged) {
            meter.record(total - charged)?; // final figure may exceed what the stream showed
        }
        if res["is_error"].as_bool().unwrap_or(false) || !status.success() {
            let why = res["result"].as_str().unwrap_or("error");
            let acct = account_error.map_or(String::new(), |e| format!(" [{e}]"));
            return Err(Error::Harness(format!("claude reported an error{acct}: {why}")));
        }
        Ok(res["result"].as_str().unwrap_or("").trim().to_string())
    }
}

struct RemoveOnDrop(PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
