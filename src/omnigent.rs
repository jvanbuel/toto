//! Omnigent harness: runs the project's own agent directory inside the project's environment,
//! behind the credential proxy.
//!
//! toto generates nothing. The approved agent directory (`agent`) is unpacked into the container
//! as is, the prompt is written to a file, and `omnigent run <dir> -p "<prompt>"` runs with a
//! dummy credential in its environment. Model calls reach the API through the in-container relay
//! and the host proxy, which swaps in the real credential and meters the tokens.

use crate::agent::{self, CONTAINER_AGENT_DIR};
use crate::harness::Harness;
use crate::manifest::TaskManifest;
use crate::meter::UsageMeter;
use crate::proxy::{AuthProxy, Provider};
use crate::sandbox::{exec_io, Workspace, PROXY_ADDR};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A project's approved agent, as the harness needs it.
#[derive(Debug, Clone)]
pub struct ApprovedAgent {
    /// The agent directory as a tar (`agent::pack`).
    pub tar: Vec<u8>,
    /// Omnigent harness named in its config, e.g. `claude-sdk`.
    pub harness: String,
}

pub struct OmnigentHarness {
    pub proxy: Arc<AuthProxy>,
    /// Which API the proxy fronts; a project whose harness needs the other one is refused.
    pub provider: Provider,
    pub agents: BTreeMap<String, ApprovedAgent>,
}

impl OmnigentHarness {
    pub fn new(proxy: Arc<AuthProxy>, provider: Provider) -> Self {
        Self { proxy, provider, agents: BTreeMap::new() }
    }
}

impl Harness for OmnigentHarness {
    fn run(&self, task: &TaskManifest, ws: &Workspace, meter: &mut UsageMeter) -> Result<String> {
        let agent = self.agents.get(&task.project_id).ok_or_else(|| Error::Harness(format!("no approved agent for project `{}`", task.project_id)))?;
        match agent::provider_for(&agent.harness) {
            Some(p) if p == self.provider => {}
            Some(p) => return Err(Error::Harness(format!("project `{}` uses harness `{}`, which needs {p:?} credentials; this runner has {:?}", task.project_id, agent.harness, self.provider))),
            None => return Err(Error::Harness(format!("unknown harness `{}`", agent.harness))),
        }
        let (name, head) = ws.exec_prefix.split_last().ok_or_else(|| Error::Harness("the omnigent harness needs a container sandbox".into()))?;
        let base_url = format!("http://{PROXY_ADDR}");
        let mut envs: Vec<(String, String)> = vec![("HOME".into(), "/tmp/home".into()), ("TERM".into(), "dumb".into()), ("DISABLE_AUTOUPDATER".into(), "1".into()), ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into())];
        match self.provider {
            Provider::Anthropic => envs.extend([("ANTHROPIC_BASE_URL".into(), base_url), ("ANTHROPIC_AUTH_TOKEN".into(), "not-a-credential".into())]),
            Provider::OpenAi => envs.extend([("OPENAI_BASE_URL".into(), format!("{base_url}/v1")), ("OPENAI_API_KEY".into(), "not-a-credential".into())]),
        }
        let mut prefix: Vec<String> = head.to_vec();
        for (k, v) in &envs {
            prefix.extend(["-e".into(), format!("{k}={v}")]);
        }
        prefix.extend(["-w".into(), "/workspace".into(), name.clone()]);
        let sh = Workspace { task_id: ws.task_id.clone(), path: ws.path.clone(), exec_prefix: prefix };

        // The approved agent directory and the prompt go in through stdin: nothing of the task
        // appears in a process list or hits argument-length limits.
        let t = Duration::from_secs(60);
        let unpack = format!("rm -rf {d} && mkdir -p {d} /tmp/home && tar -x -f - -C {d}", d = CONTAINER_AGENT_DIR);
        let out = exec_io(&sh, &["sh", "-c", &unpack], Some(&agent.tar), t, 4096)?;
        if !out.status.success() {
            return Err(Error::Harness(format!("could not place the agent directory (the image must provide `tar`): {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        exec_io(&sh, &["sh", "-c", "cat > /tmp/prompt.txt"], Some(task.prompt.as_bytes()), t, 4096)?;

        let start = self.proxy.tokens();
        let mut argv = sh.exec_prefix.clone();
        argv.extend(["sh".into(), "-c".into(), format!("exec omnigent run {CONTAINER_AGENT_DIR} -p \"$(cat /tmp/prompt.txt)\"")]);
        let mut child = Command::new(&argv[0]).args(&argv[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let out = std::thread::spawn(move || {
            let mut b = String::new();
            let _ = so.read_to_string(&mut b);
            b
        });
        let err = std::thread::spawn(move || {
            let mut b = String::new();
            let _ = se.read_to_string(&mut b);
            b
        });
        let deadline = Instant::now() + Duration::from_secs(task.sandbox_profile.timeout_secs);
        let mut charged = 0u64;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            let used = self.proxy.tokens().saturating_sub(start);
            if used > charged {
                let delta = used - charged;
                charged = used;
                if let Err(e) = meter.record(delta) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Harness(format!("timed out after {}s", task.sandbox_profile.timeout_secs)));
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let (stdout, stderr) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
        let used = self.proxy.tokens().saturating_sub(start);
        if used > charged {
            meter.record(used - charged)?;
        }
        if !status.success() {
            let hint = if status.code() == Some(127) { " (is `omnigent` installed in the project's image?)" } else { "" };
            let tail: Vec<&str> = stderr.lines().rev().take(3).collect();
            return Err(Error::Harness(format!("omnigent exited with {status}{hint}: {}", tail.into_iter().rev().collect::<Vec<_>>().join(" | "))));
        }
        Ok(stdout.trim().to_string())
    }
}
