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
        c.push(Check::new(Level::Warn, "projects", "none: nothing will run (`toto projects add owner/name`)"));
    } else {
        c.push(Check::new(Level::Ok, "projects", format!("{} supported", cfg.projects.len())));
    }
    if cfg.policy.allowed_kinds.is_empty() || cfg.policy.project_shares.is_empty() {
        c.push(Check::new(Level::Warn, "policy", "no allowed kinds or project shares: every task will be refused"));
    } else {
        c.push(Check::new(Level::Ok, "policy", format!("daily cap {} tokens, {} kinds", cfg.policy.daily_token_cap, cfg.policy.allowed_kinds.len())));
    }
    for e in &cfg.queues {
        let name = e.describe();
        c.push(match e.build().and_then(|q| q.available()) {
            Ok(tasks) => Check::new(Level::Ok, "queue", format!("{name} reachable, {} tasks available", tasks.len())),
            Err(err) => Check::new(Level::Fail, "queue", format!("{name}: {err}")),
        });
        if matches!(e, QueueEndpoint::Github { token_file: None, .. }) {
            c.push(Check::new(Level::Warn, "queue", format!("{name} has no token: reads only, at GitHub's low anonymous rate limit; claiming and submitting need a token")));
        }
    }
    if cfg.queues.is_empty() {
        c.push(if cfg.queue_dir.is_dir() { Check::new(Level::Ok, "queue", format!("{} (spool directory)", cfg.queue_dir.display())) } else { Check::new(Level::Warn, "queue", format!("{} does not exist yet", cfg.queue_dir.display())) });
    }

    match &cfg.sandbox {
        SandboxConfig::Dir => c.push(Check::new(Level::Warn, "sandbox", "`dir` gives no isolation (development only)")),
        SandboxConfig::Docker { bin, runtime, nested_userns, network, relay } => {
            // `probe` covers the daemon, every approved image, the relay binary and the network fence.
            match cfg.build_sandbox().probe() {
                Ok(()) => c.push(Check::new(Level::Ok, "sandbox", format!("{bin}{}", runtime.as_deref().map_or(String::new(), |r| format!(" (runtime {r})"))))),
                Err(e) => c.push(Check::new(Level::Fail, "sandbox", e.to_string())),
            }
            if relay.is_none() {
                c.push(Check::new(Level::Fail, "sandbox", "`relay` is not set: build the static toto-relay binary and point the sandbox config at it"));
            }
            match network {
                Some(net) => c.push(Check::new(Level::Ok, "network", format!("`{net}` is the fenced network for agents that need one"))),
                None => c.push(Check::new(Level::Warn, "network", "none configured: projects whose agents need a network are refused (`toto net-setup`)")),
            }
            if *nested_userns && runtime.as_deref().is_some_and(|r| r.contains("runsc")) {
                c.push(Check::new(Level::Fail, "nested sandbox", "gVisor (runsc) cannot run a nested bubblewrap"));
            }
            if run(bin, &["info", "--format", "{{.SecurityOptions}}"]).is_some_and(|s| s.contains("apparmor")) && *nested_userns {
                c.push(Check::new(Level::Warn, "apparmor", "AppArmor is active; the nested sandbox is untested with `docker-default`"));
            }
            for (id, a) in &cfg.environments {
                let mut notes = vec![];
                if a.agent.needs_network && network.is_none() {
                    notes.push("needs a network, none configured");
                }
                if a.agent.needs_nested_sandbox() && !nested_userns {
                    notes.push("uses Omnigent's sandbox, needs `nested_userns: true`");
                }
                let tools = run(bin, &["run", "--rm", "--network", "none", "--entrypoint", "sh", &a.pinned(), "-c", "command -v omnigent >/dev/null && echo omnigent; command -v tar >/dev/null && echo tar; command -v bwrap >/dev/null && echo bwrap"]).unwrap_or_default();
                if !tools.contains("omnigent") {
                    notes.push("image has no `omnigent`");
                }
                if !tools.contains("tar") {
                    notes.push("image has no `tar`");
                }
                if a.agent.needs_nested_sandbox() && !tools.contains("bwrap") {
                    notes.push("image has no `bwrap` for Omnigent's sandbox");
                }
                let level = if notes.is_empty() { Level::Ok } else { Level::Fail };
                c.push(Check::new(level, "environment", format!("{id}: {} ({}, {}){}", a.image, a.info.short(), a.agent.harness, if notes.is_empty() { String::new() } else { format!(": {}", notes.join("; ")) })));
            }
            match crate::prebuild::cli_version(crate::prebuild::DEFAULT_CLI) {
                Some(v) => c.push(Check::new(Level::Ok, "prebuild", format!("dev container CLI {v}: projects without a published image can be added"))),
                None => c.push(Check::new(Level::Warn, "prebuild", "dev container CLI not found: only projects with a published image can be added (`npm i -g @devcontainers/cli`)")),
            }
        }
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
            if let Some(mine) = cfg.harness_provider() {
                for (id, a) in &cfg.environments {
                    if a.agent.provider().is_some_and(|p| p != mine) {
                        c.push(Check::new(Level::Fail, "harness", format!("{id} uses `{}`, which needs {:?} credentials; this runner has {mine:?}", a.agent.harness, a.agent.provider().unwrap())));
                    }
                }
            }
        }
    }
    c
}

fn harness_name(h: &HarnessConfig) -> String {
    match h {
        HarnessConfig::Echo { .. } => "echo".into(),
        HarnessConfig::Omnigent { provider, .. } => format!("omnigent in the project's image, {provider:?} credential"),
    }
}

/// True when no check failed.
pub fn passed(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.level != Level::Fail)
}
