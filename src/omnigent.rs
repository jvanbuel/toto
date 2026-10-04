//! `OmnigentHarness`: runs tasks through a local Omnigent install (ADR 4) in the one mode that
//! keeps the contributor's login away from task content (ADR 5, "Findings").
//!
//! The generated agent sets `os_env.sandbox.allow_network: false`. Omnigent then runs the AI
//! CLI *unwrapped*, with its native tools disabled, and routes all file and shell access
//! through its own sandboxed helpers (bwrap on Linux, Seatbelt on macOS) rooted at the task
//! workspace. The login stays with the trusted CLI process; task commands cannot see it.
//!
//! Omnigent's helpers, not the `togra` sandbox, isolate the task here, so this harness needs a
//! sandbox that exposes a host workspace directory (`dir` or `bwrap`). That fallback mode is not
//! a documented Omnigent setting, so the installed version is pinned and the probe in
//! `scripts/probe-omnigent-sandbox.py` should be re-run on upgrades.

use crate::harness::Harness;
use crate::manifest::TaskManifest;
use crate::meter::UsageMeter;
use crate::sandbox::Workspace;
use crate::{Error, Result};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct OmnigentHarness {
    pub bin: String,
    /// Where the local Omnigent server answers (used only to read per-session token usage).
    pub server_url: String,
    /// Omnigent harness name, e.g. `claude-sdk` or `codex`.
    pub harness: String,
    /// Required `omnigent --version` prefix, e.g. `0.16.`.
    pub version_prefix: String,
    pub agent_yaml: PathBuf,
    pub poll: Duration,
}

/// The agent spec handed to Omnigent. Prompt injection from the task is assumed, so the agent is
/// told nothing it must keep secret and is given no network.
pub fn agent_yaml() -> String {
    let sandbox = if cfg!(target_os = "macos") { "darwin_seatbelt" } else { "linux_bwrap" };
    format!(
        "spec_version: 1\nname: togra-task\ndescription: A task donated through togra\n\
         executor:\n  type: omnigent\n  config:\n    harness: claude-sdk\n\
         prompt: |\n  You are completing one self-contained task for a public-good project. \
Work only inside the current directory and reply with the final result only.\n\
         os_env:\n  type: caller_process\n  cwd: \".\"\n  sandbox:\n    type: {sandbox}\n    \
write_paths: [\".\"]\n    allow_network: false\n"
    )
}

impl OmnigentHarness {
    pub fn new(state_dir: &Path) -> Result<Self> {
        let agent_yaml = state_dir.join("togra-agent.yaml");
        std::fs::write(&agent_yaml, self::agent_yaml())?;
        Ok(Self {
            bin: "omnigent".into(),
            server_url: "http://127.0.0.1:6767".into(),
            harness: "claude-sdk".into(),
            version_prefix: "0.16.".into(),
            agent_yaml,
            poll: Duration::from_secs(5),
        })
    }

    /// Fails unless the pinned Omnigent version is installed.
    pub fn check_version(&self) -> Result<()> {
        let out = Command::new(&self.bin).arg("--version").output().map_err(|e| Error::Harness(format!("cannot run `{}`: {e}", self.bin)))?;
        let v = String::from_utf8_lossy(&out.stdout);
        match v.split_whitespace().nth(1) {
            Some(ver) if ver.starts_with(&self.version_prefix) => Ok(()),
            _ => Err(Error::Harness(format!("unsupported Omnigent `{}`; need {}x", v.trim(), self.version_prefix))),
        }
    }

    /// Tokens used by a session so far: input + output + cache creation (cache reads are free
    /// to the quota and are excluded).
    fn session_tokens(&self, session: &str) -> Option<u64> {
        let url = format!("{}/v1/sessions/{session}", self.server_url.trim_end_matches('/'));
        let mut resp = ureq::get(&url).config().timeout_global(Some(Duration::from_secs(5))).build().call().ok()?;
        let v: serde_json::Value = serde_json::from_str(&resp.body_mut().read_to_string().ok()?).ok()?;
        let by_model = v.get("usage_by_model")?.as_object()?;
        let n = |m: &serde_json::Value, k: &str| m.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
        Some(by_model.values().map(|m| n(m, "input_tokens") + n(m, "output_tokens") + n(m, "cache_creation_input_tokens")).sum())
    }
}

/// Extracts the session id from `Omnigent session: http://host/c/<id>`.
pub fn parse_session_id(line: &str) -> Option<String> {
    let rest = line.strip_prefix("Omnigent session:")?;
    let id = rest.rsplit("/c/").next()?.trim();
    (!id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric())).then(|| id.to_string())
}

impl Harness for OmnigentHarness {
    fn probe(&self) -> Result<()> {
        self.check_version()
    }

    fn run(&self, task: &TaskManifest, ws: &Workspace, meter: &mut UsageMeter) -> Result<String> {
        if ws.path.as_os_str().is_empty() {
            return Err(Error::Harness("the omnigent harness needs a host workspace directory (sandbox `dir` or `bwrap`)".into()));
        }
        let mut child = Command::new(&self.bin)
            .args(["run"])
            .arg(&self.agent_yaml)
            .args(["--harness", &self.harness, "-p", &task.prompt])
            .current_dir(&ws.path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Harness(format!("cannot run `{}`: {e}", self.bin)))?;

        let (id_tx, id_rx) = mpsc::channel::<String>();
        let mut stdout = child.stdout.take().unwrap();
        let out = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stdout.read_to_string(&mut s);
            s
        });
        let stderr = child.stderr.take().unwrap();
        let err = std::thread::spawn(move || {
            let mut text = String::new();
            for line in BufReader::new(stderr).lines().map_while(std::result::Result::ok) {
                if let Some(id) = parse_session_id(&line) {
                    let _ = id_tx.send(id);
                }
                text.push_str(&line);
                text.push('\n');
            }
            text
        });

        let deadline = Instant::now() + Duration::from_secs(task.sandbox_profile.timeout_secs);
        let (mut session, mut seen, mut next_poll) = (None::<String>, 0u64, Instant::now());
        let charge = |h: &Self, session: &Option<String>, seen: &mut u64, meter: &mut UsageMeter| -> Result<()> {
            if let Some(total) = session.as_deref().and_then(|s| h.session_tokens(s)) {
                if total > *seen {
                    let delta = total - *seen;
                    *seen = total;
                    meter.record(delta)?;
                }
            }
            Ok(())
        };
        let status = loop {
            if session.is_none() {
                session = id_rx.try_recv().ok();
            }
            if let Some(s) = child.try_wait()? {
                break s;
            }
            let stop = if Instant::now() >= deadline {
                Some(Error::Harness(format!("timed out after {}s", task.sandbox_profile.timeout_secs)))
            } else if Instant::now() >= next_poll {
                next_poll = Instant::now() + self.poll;
                charge(self, &session, &mut seen, meter).err()
            } else {
                None
            };
            if let Some(e) = stop {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let (stdout, stderr) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
        if session.is_none() {
            session = id_rx.try_recv().ok();
        }
        charge(self, &session, &mut seen, meter)?; // final usage, may still abort the result
        if !status.success() {
            let tail: Vec<&str> = stderr.lines().rev().take(3).collect();
            return Err(Error::Harness(format!("omnigent exited with {status}: {}", tail.into_iter().rev().collect::<Vec<_>>().join(" | "))));
        }
        Ok(stdout.trim().to_string())
    }
}
