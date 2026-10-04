//! `ClaudeCliHarness`: runs a task with the official `claude` CLI, authenticated by the
//! contributor's own Claude subscription (ADR 11).
//!
//! The agent loop and the login stay on the host. The CLI is started with every built-in tool
//! turned off and exactly one MCP server, `sandbox`, whose command is
//! `docker exec -i <container> /toto/mcp-exec`, so everything the agent does to files or
//! processes happens inside the hardened container (ADR 10). The CLI runs from a scratch
//! directory holding only the task's skills, with a dedicated config dir and a cleared
//! environment, so the contributor's own settings, memory, hooks, MCP servers and skills never
//! reach a task, and no API key in the environment can change who is billed.
//!
//! Subscription auth uses a long-lived token from `claude setup-token`, stored by `toto login`
//! with mode 0600 and passed to the CLI process only. Never use `--bare`: it ignores
//! subscription login.

use crate::harness::Harness;
use crate::context::{McpEntry, ProjectContext};
use crate::manifest::TaskManifest;
use crate::meter::UsageMeter;
use crate::proxy::AuthProxy;
use crate::sandbox::{Workspace, AGENT_DIR, PROXY_ADDR};
use crate::{Error, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// Where the agent process runs.
pub enum Placement {
    /// On the host, with only an MCP bridge into the container (ADR 10, 11).
    Host,
    /// Inside the task container, with no credential: model calls go through the credential proxy
    /// (ADR 12). Built-in tools run natively in the container.
    Container(Arc<AuthProxy>),
}

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
    pub placement: Placement,
    /// Executable name under `AGENT_DIR` in container placement (the mounted agent's file name).
    pub agent_name: String,
}

impl ClaudeCliHarness {
    pub fn new(state_dir: &Path, token_file: PathBuf) -> Result<Self> {
        let (home_dir, runs_dir) = (state_dir.join("claude-home"), state_dir.join("runs"));
        std::fs::create_dir_all(&home_dir)?;
        std::fs::create_dir_all(&runs_dir)?;
        Ok(Self { bin: "claude".into(), token_file, home_dir, runs_dir, model: None, max_turns: 40, placement: Placement::Host, agent_name: "claude".into() })
    }

    /// Runs the agent inside the container behind `proxy` instead of on the host.
    pub fn in_container(mut self, proxy: Arc<AuthProxy>) -> Self {
        self.placement = Placement::Container(proxy);
        self
    }

    /// Reads the token, refusing a file that other users can read.
    pub fn read_token(&self) -> Result<String> {
        read_secret(&self.token_file)
    }
}

/// Reads a secret file (token or API key), refusing one that other users can read.
pub fn read_secret(path: &Path) -> Result<String> {
    let meta = std::fs::metadata(path).map_err(|e| Error::Harness(format!("no credential at {} ({e}); run `toto login`", path.display())))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(Error::Harness(format!("{} is readable by others; chmod 600 it", path.display())));
    }
    let t = std::fs::read_to_string(path)?.trim().to_string();
    if t.is_empty() {
        return Err(Error::Harness(format!("{} is empty; run `toto login`", path.display())));
    }
    Ok(t)
}

/// Stores a token with mode 0600 (created with that mode, never briefly wider).
pub fn save_token(path: &Path, token: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(token.trim().as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// MCP config for `--mcp-config`, built from the project's `.mcp.json`:
/// - remote servers pass through (the host connects; policy has already checked the host);
/// - command servers are run **inside the sandbox container** as `docker exec -i [-e K=V] <name> cmd args`,
///   never on the host;
/// - the runner's own bridge is inserted last so a project can never replace it.
pub fn mcp_config(ctx: &ProjectContext, exec_prefix: &[String], bridge: &[String]) -> Value {
    let mut servers = serde_json::Map::new();
    for m in &ctx.mcp {
        match m {
            McpEntry::Remote { name, sse, url } => {
                servers.insert(name.clone(), json!({"type": if *sse { "sse" } else { "http" }, "url": url}));
            }
            McpEntry::Stdio { name, command, args, env } => {
                let (container, head) = exec_prefix.split_last().expect("a container sandbox has an exec prefix");
                let mut argv: Vec<String> = head.to_vec();
                for (k, v) in env {
                    argv.extend(["-e".into(), format!("{k}={v}")]);
                }
                argv.push(container.clone());
                argv.push(command.clone());
                argv.extend(args.iter().cloned());
                servers.insert(name.clone(), json!({"command": argv[0], "args": &argv[1..]}));
            }
        }
    }
    servers.insert(crate::manifest::BRIDGE_SERVER_NAME.into(), json!({"command": bridge[0], "args": &bridge[1..]}));
    json!({"mcpServers": servers})
}

/// Writes the project's skills and instruction files where the CLI looks for them. Skills go
/// under `.claude/skills`; `AGENTS.md` is made visible to Claude Code through a `CLAUDE.md` import.
pub fn write_context(dir: &Path, ctx: &ProjectContext) -> Result<()> {
    for sk in &ctx.skills {
        for (path, data) in &sk.files {
            let target = dir.join(".claude/skills").join(&sk.name).join(path);
            std::fs::create_dir_all(target.parent().unwrap())?;
            std::fs::write(target, data)?;
        }
    }
    for (name, text) in &ctx.instructions {
        std::fs::write(dir.join(name), text)?;
    }
    if ctx.instructions.contains_key("AGENTS.md") && !ctx.instructions.contains_key("CLAUDE.md") {
        std::fs::write(dir.join("CLAUDE.md"), "@AGENTS.md\n")?;
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
    fn context_in_workspace(&self) -> bool {
        matches!(self.placement, Placement::Container(_))
    }

    fn probe(&self) -> Result<()> {
        if matches!(self.placement, Placement::Container(_)) {
            return Ok(()); // the sandbox probe checks that the agent binary runs in the image
        }
        self.read_token()?;
        let out = Command::new(&self.bin).arg("--version").output().map_err(|e| Error::Harness(format!("cannot run `{}`: {e}", self.bin)))?;
        if out.status.success() { Ok(()) } else { Err(Error::Harness("`claude --version` failed".into())) }
    }

    fn supports_context(&self) -> bool {
        true
    }

    fn run(&self, task: &TaskManifest, ctx: &ProjectContext, ws: &Workspace, meter: &mut UsageMeter) -> Result<String> {
        let bridge = ws.bridge_argv().ok_or_else(|| Error::Harness("the claude harness needs a container sandbox with the exec bridge".into()))?;
        let skill_tool = !ctx.skills.is_empty();
        let in_container = matches!(self.placement, Placement::Container(_));
        let proxy_start = if let Placement::Container(p) = &self.placement { p.tokens() } else { 0 };
        let run_dir = self.runs_dir.join(crate::sandbox::DockerSandbox::container_name(&task.id));
        std::fs::create_dir_all(&run_dir)?;
        let _cleanup = RemoveOnDrop(run_dir.clone());

        let common = ["-p", "--output-format", "stream-json", "--verbose", "--no-session-persistence", "--setting-sources", "project", "--permission-mode", "dontAsk", "--permission-prompts", "none"];
        let (mut cmd, allowed_builtins): (Command, Vec<&str>) = if let Placement::Container(_) = &self.placement {
            if ctx.mcp.iter().any(|m| matches!(m, McpEntry::Remote { .. })) {
                return Err(Error::Harness("remote MCP servers are unreachable from a container without network; use command servers or the host placement".into()));
            }
            // The agent runs in the container. Project context (skills, CLAUDE.md, .mcp.json) was
            // unpacked into /workspace by the runner; command servers start there, in the sandbox.
            let builtins: Vec<&str> = ["Bash", "Read", "Edit", "Write", "Glob", "Grep"].into_iter().chain(skill_tool.then_some("Skill")).collect();
            let allowed: Vec<String> = builtins.iter().map(|b| b.to_string()).chain(ctx.mcp.iter().map(|m| format!("mcp__{}", m.name()))).collect();
            let (name, head) = ws.exec_prefix.split_last().expect("a container sandbox has an exec prefix");
            let mut c = Command::new(&head[0]);
            c.args(&head[1..]);
            for e in [format!("ANTHROPIC_BASE_URL=http://{PROXY_ADDR}"), "ANTHROPIC_AUTH_TOKEN=not-a-credential".into(), "HOME=/tmp/home".into(), "CLAUDE_CONFIG_DIR=/tmp/home/.claude".into(), "DISABLE_AUTOUPDATER=1".into(), "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1".into(), "TERM=dumb".into()] {
                c.args(["-e", &e]);
            }
            c.args(["-w", "/workspace", name, &format!("{AGENT_DIR}/{}", self.agent_name)]).args(common).args(["--tools", &builtins.join(",")]).arg(format!("--allowedTools={}", allowed.join(",")));
            // Only what the CLI needs to reach the container runtime: nothing else from the host.
            c.env_clear();
            for k in ["PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "CONTAINER_HOST", "XDG_RUNTIME_DIR", "TMPDIR"] {
                if let Ok(v) = std::env::var(k) {
                    c.env(k, v);
                }
            }
            (c, builtins)
        } else {
            let token = self.read_token()?;
            write_context(&run_dir, ctx)?;
            // The raw project `.mcp.json` is never written: only the translated config is passed.
            let mcp_path = run_dir.join("toto-mcp.json");
            std::fs::write(&mcp_path, serde_json::to_vec(&mcp_config(ctx, &ws.exec_prefix, &bridge))?)?;
            // Built-in tools stay off, except `Skill` (loads instructions, runs nothing) when the project ships skills.
            let allowed: Vec<String> = ctx.mcp.iter().map(|m| format!("mcp__{}", m.name())).chain([format!("mcp__{}", crate::manifest::BRIDGE_SERVER_NAME)]).chain(skill_tool.then(|| "Skill".to_string())).collect();
            let mut c = Command::new(&self.bin);
            c.args(common)
                .args(["--tools", if skill_tool { "Skill" } else { "" }])
                .args(["--strict-mcp-config", "--mcp-config"]).arg(&mcp_path)
                .arg(format!("--allowedTools={}", allowed.join(",")))
                .current_dir(&run_dir)
                .env_clear()
                .envs(cli_env(&self.home_dir, &token));
            (c, if skill_tool { vec!["Skill"] } else { vec![] })
        };
        cmd.args(["--max-turns", &self.max_turns.to_string()]);
        if let Some(m) = &self.model {
            cmd.args(["--model", m]);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Harness(format!("cannot run the agent: {e}")))?;

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
                            let builtin = ev["tools"].as_array().into_iter().flatten().filter_map(Value::as_str).find(|t| !t.starts_with("mcp__") && !allowed_builtins.contains(t));
                            if let Some(t) = builtin {
                                return Err(abort(&mut child, Error::Harness(format!("built-in tool `{t}` is enabled; refusing to run"))));
                            }
                            if ev["mcp_server_errors"].as_array().is_some_and(|a| !a.is_empty()) {
                                return Err(abort(&mut child, Error::Harness(format!("mcp server config rejected: {}", ev["mcp_server_errors"]))));
                            }
                            let down = ev["mcp_servers"].as_array().into_iter().flatten().find(|s| !in_container && s["name"] == crate::manifest::BRIDGE_SERVER_NAME && s["status"] != "connected");
                            if let Some(s) = down {
                                return Err(abort(&mut child, Error::Harness(format!("sandbox bridge did not connect: {s}"))));
                            }
                        }
                        (Some("system"), Some("api_retry")) => {
                            if let Some(e) = ev["error"].as_str().filter(|e| ACCOUNT_ERRORS.contains(e)) {
                                account_error = Some(e.to_string());
                            }
                        }
                        (Some("assistant"), _) if !in_container => {
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
            // In a container the proxy counts the tokens itself, independent of anything the agent says.
            if let Placement::Container(p) = &self.placement {
                let used = p.tokens().saturating_sub(proxy_start);
                if used > charged {
                    let delta = used - charged;
                    charged = used;
                    if let Err(e) = meter.record(delta) {
                        return Err(abort(&mut child, e));
                    }
                }
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
        if let Some(total) = res.get("usage").map(usage_tokens).filter(|t| *t > charged && !in_container) {
            meter.record(total - charged)?; // final figure may exceed what the stream showed
        }
        if let Placement::Container(p) = &self.placement {
            let used = p.tokens().saturating_sub(proxy_start); // the last response may land after the final poll
            if used > charged {
                meter.record(used - charged)?;
            }
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
