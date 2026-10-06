//! `toto doctor`: checks the whole setup and says what works, what is risky and what is missing.
//! Every check runs independently, so one failure does not hide the others.

use crate::config::{Config, HarnessConfig, QueueEndpoint, SandboxConfig};
use crate::queue::QueueClient;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub level: Level,
    pub name: &'static str,
    pub detail: String,
}

impl Check {
    fn new(level: Level, name: &'static str, detail: impl Into<String>) -> Self {
        Self { level, name, detail: detail.into() }
    }
}

impl std::fmt::Display for Check {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = match self.level {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
        };
        write!(f, "[{tag}] {}: {}", self.name, self.detail)
    }
}

fn run(bin: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(bin).args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

pub fn run_all(cfg: &Config) -> Vec<Check> {
    let mut c = Vec::new();

    match std::fs::metadata(&cfg.key_file) {
        Ok(m) if std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o077 != 0 => c.push(Check::new(Level::Warn, "runner key", format!("{} is readable by others (chmod 600)", cfg.key_file.display()))),
        Ok(_) => c.push(Check::new(Level::Ok, "runner key", cfg.key_file.display().to_string())),
        Err(_) => c.push(Check::new(Level::Warn, "runner key", "not created yet (the daemon creates it on first start)")),
    }
    if cfg.projects.is_empty() {
        c.push(Check::new(Level::Warn, "projects", "no trusted project keys: nothing will run"));
    } else {
        c.push(Check::new(Level::Ok, "projects", format!("{} trusted", cfg.projects.len())));
    }
    if cfg.policy.allowed_kinds.is_empty() || cfg.policy.project_shares.is_empty() {
        c.push(Check::new(Level::Warn, "policy", "no allowed kinds or project shares: every task will be refused"));
    } else {
        c.push(Check::new(Level::Ok, "policy", format!("daily cap {} tokens, {} kinds", cfg.policy.daily_token_cap, cfg.policy.allowed_kinds.len())));
    }
    for e in &cfg.queues {
        let name = e.describe();
        let plain = matches!(e, QueueEndpoint::Http { url, .. } if url.starts_with("http://") && !url.contains("//127.") && !url.contains("//localhost"));
        c.push(match e.build().and_then(|q| q.available()) {
            Ok(tasks) if plain => Check::new(Level::Warn, "queue", format!("{name} reachable ({} tasks) but uses plain http; tasks and results cross the network unencrypted", tasks.len())),
            Ok(tasks) => Check::new(Level::Ok, "queue", format!("{name} reachable, {} tasks available", tasks.len())),
            Err(err) => Check::new(Level::Fail, "queue", format!("{name}: {err}")),
        });
        if matches!(e, QueueEndpoint::Github { token_file: None, .. }) {
            c.push(Check::new(Level::Warn, "queue", format!("{name} has no token: reads only, at GitHub's low anonymous rate limit; claiming and submitting need a token")));
        }
    }
    if cfg.queues.is_empty() {
        c.push(if cfg.queue_dir.is_dir() { Check::new(Level::Ok, "queue", cfg.queue_dir.display().to_string()) } else { Check::new(Level::Warn, "queue", format!("{} does not exist yet", cfg.queue_dir.display())) });
    }

    match &cfg.sandbox {
        SandboxConfig::Dir => c.push(Check::new(Level::Warn, "sandbox", "`dir` gives no isolation (development only)")),
        SandboxConfig::Bwrap => c.push(match cfg.build_sandbox().probe() {
            Ok(()) => Check::new(Level::Ok, "sandbox", "bubblewrap"),
            Err(e) => Check::new(Level::Fail, "sandbox", e.to_string()),
        }),
        SandboxConfig::Docker { bin, image, runtime, nested_userns, network, .. } => {
            docker_checks(&mut c, cfg, bin, image, runtime.as_deref(), *nested_userns, network.as_deref());
        }
    }

    for (id, env) in &cfg.environments {
        c.push(Check::new(Level::Ok, "environment", format!("{id}: {} (approved, tasks run exactly this digest; `toto projects update {id}` checks for a new one)", env.pinned())));
    }
    // Building the runner also validates the harness settings and reads the credential files.
    match cfg.build() {
        Err(e) => c.push(Check::new(Level::Fail, "harness", e.to_string())),
        Ok(r) => {
            c.push(match r.harness.probe() {
                Ok(()) => Check::new(Level::Ok, "harness", harness_name(&cfg.harness)),
                Err(e) => Check::new(Level::Fail, "harness", e.to_string()),
            });
            if matches!(&cfg.harness, HarnessConfig::Echo { .. }) {
                c.push(Check::new(Level::Warn, "harness", "`echo` does not use a model (placeholder)"));
            }
        }
    }
    c
}

fn harness_name(h: &HarnessConfig) -> String {
    match h {
        HarnessConfig::Echo { .. } => "echo".into(),
        HarnessConfig::Claude { .. } => "claude CLI".into(),
        HarnessConfig::Omnigent { harness, .. } => format!("omnigent ({harness})"),
    }
}

fn docker_checks(c: &mut Vec<Check>, cfg: &Config, bin: &str, image: &str, runtime: Option<&str>, nested: bool, network: Option<&str>) {
    // `build_sandbox().probe()` covers the daemon, the image, the agent binary and the network fence.
    match cfg.build_sandbox().probe() {
        Ok(()) => c.push(Check::new(Level::Ok, "sandbox", format!("{bin}, image `{image}`"))),
        Err(e) => {
            c.push(Check::new(Level::Fail, "sandbox", e.to_string()));
            return;
        }
    }
    if let Some(net) = network {
        // The probe above already refused an unfenced network, so reaching here means it held.
        c.push(Check::new(Level::Ok, "network", format!("`{net}` is fenced (a container could not reach this host)")));
    }
    if nested {
        if runtime.is_some_and(|r| r.contains("runsc")) {
            c.push(Check::new(Level::Fail, "nested sandbox", "gVisor (runsc) cannot run a nested bubblewrap"));
        } else {
            let tools = run(bin, &["run", "--rm", "--network", "none", image, "sh", "-c", "command -v bwrap >/dev/null && echo bwrap; test -d /run/lakebox && echo marker"]).unwrap_or_default();
            c.push(if tools.contains("bwrap") { Check::new(Level::Ok, "nested sandbox", "bubblewrap is in the image") } else { Check::new(Level::Fail, "nested sandbox", "bubblewrap is missing from the image (apt-get install bubblewrap)") });
            if !tools.contains("marker") {
                c.push(Check::new(Level::Warn, "nested sandbox", "image lacks /run/lakebox: Omnigent cannot mount /proc in the nested sandbox (see the example Dockerfile)"));
            }
        }
        if run(bin, &["info", "--format", "{{.SecurityOptions}}"]).is_some_and(|s| s.contains("apparmor")) {
            c.push(Check::new(Level::Warn, "apparmor", "AppArmor is active; the nested sandbox is untested with `docker-default` (check `toto doctor` on a real task)"));
        }
    }
}

/// True when no check failed.
pub fn passed(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.level != Level::Fail)
}
