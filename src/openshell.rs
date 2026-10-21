//! NVIDIA OpenShell as a sandbox backend (spike; see docs/spikes/openshell.md).
//!
//! OpenShell runs the project's image as a workload with networking off, confined by Landlock and
//! seccomp, next to a trusted supervisor that mediates every outbound connection against a policy.
//! toto keeps its own credential proxy in the path, because metering, the overrun abort and the
//! pause at the reserve live there: the proxy listens on TCP on the host with a per-runner key,
//! the sandbox's policy allows exactly that one endpoint (`host.openshell.internal`), and the agent
//! presents the key instead of a credential. No provider credential is ever given to OpenShell.
//!
//! Driven through the `openshell` CLI, against the private gateway toto runs itself
//! (`crate::openshell_gateway`) or, if configured, one the contributor runs.

use crate::manifest::{SandboxProfile, TaskManifest};
use crate::sandbox::{collect_via_exec, exec_io, Environment, ExecStyle, ProxyEndpoint, Sandbox, Workspace};
use crate::{Error, Result};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

/// The name the gateway host has inside a sandbox's policy.
pub const HOST_ALIAS: &str = "host.openshell.internal";

/// The task's work directory: toto's own tmpfs (OpenShell reserves `/sandbox`).
pub const WORKDIR: &str = "/work";

/// Most bytes sent over one `exec`'s stdin (OpenShell refuses more than 4 MiB).
const STDIN_LIMIT: usize = 3 << 20;

pub struct OpenShellSandbox {
    /// The `openshell` CLI.
    pub bin: String,
    /// Gateway to use (`--gateway <name>`); default: the CLI's active gateway.
    pub gateway: Option<String>,
    /// Environment for every CLI call (the managed gateway's isolated CLI config).
    pub env: Vec<(String, String)>,
    /// Keeps toto's managed gateway running while this sandbox exists.
    pub managed: Option<std::sync::Arc<crate::openshell_gateway::ManagedGateway>>,
    /// The approved environment per project id.
    pub environments: HashMap<String, Environment>,
    /// The approved agent's Omnigent egress rules per project id (`METHODS host/path`).
    pub egress: HashMap<String, Vec<String>>,
    /// Where sandboxes reach toto's credential proxy: `http://host.openshell.internal:<port>`.
    pub proxy: Option<ProxyEndpoint>,
    /// Policy files.
    pub scratch: PathBuf,
    baselines: Mutex<HashMap<String, BTreeMap<String, String>>>,
}

impl OpenShellSandbox {
    pub fn new(bin: &str, scratch: PathBuf) -> Self {
        Self { bin: bin.into(), gateway: None, env: vec![], managed: None, environments: HashMap::new(), egress: HashMap::new(), proxy: None, scratch, baselines: Mutex::default() }
    }

    pub fn sandbox_name(task_id: &str) -> String {
        let safe: String = task_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect::<String>().to_lowercase();
        format!("toto-{safe}")
    }

    fn cli(&self) -> Command {
        let mut c = Command::new(&self.bin);
        c.envs(self.env.iter().map(|(k, v)| (k, v)));
        if let Some(g) = &self.gateway {
            c.args(["--gateway", g]);
        }
        c
    }

    fn run(&self, args: &[&str]) -> Result<String> {
        let out = self.cli().args(args).output()?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(Error::Sandbox(format!("openshell {}: {}", args.first().unwrap_or(&""), String::from_utf8_lossy(&out.stderr).trim())))
        }
    }

    /// The policy a toto task runs under. Pure, so it is unit-tested.
    ///
    /// - the whole image is readable and nothing in it writable, except the work directory and
    ///   `/tmp`, which are size-limited tmpfs mounts (`driver_config`), as in toto's Docker
    ///   sandbox; OpenShell's own `/sandbox` is left read-only;
    /// - Landlock is a hard requirement: a kernel that cannot enforce it fails the task;
    /// - the workload runs as uid/gid 65534, never root;
    /// - the network reaches toto's proxy on the host (the proxy demands its key and forwards one
    ///   API) and, for an agent that declared them, exactly the project's egress rules, enforced
    ///   per request (method and path) by OpenShell on HTTPS port 443.
    pub fn policy_yaml(proxy_port: Option<u16>, egress: &[String]) -> Result<String> {
        let mut y = String::from(
            "version: 1\n\
             filesystem_policy:\n  include_workdir: false\n  read_only: [\"/\"]\n  read_write: [\"/work\", \"/tmp\", \"/dev/null\"]\n\
             landlock:\n  compatibility: hard_requirement\n\
             process:\n  run_as_user: \"65534\"\n  run_as_group: \"65534\"\n",
        );
        let mut rules = String::new();
        if let Some(port) = proxy_port {
            rules.push_str(&format!("  toto_proxy:\n    endpoints:\n      - host: {HOST_ALIAS}\n        port: {port}\n    binaries:\n      - path: \"/**\"\n"));
        }
        // One rule per host, with every method and path the project allowed on it.
        let mut by_host: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for r in egress {
            if !crate::agent::valid_egress_rule(r) {
                return Err(Error::Sandbox(format!("malformed egress rule `{r}`")));
            }
            let (methods, target) = r.split_once(' ').expect("validated");
            let (host, path) = target.split_once('/').expect("validated");
            if host.starts_with("*.") && host.split('.').count() < 3 {
                return Err(Error::Sandbox(format!("egress rule `{r}`: a wildcard host needs at least three labels")));
            }
            for m in methods.split(',') {
                by_host.entry(host.to_lowercase()).or_default().push((m.to_string(), format!("/{path}")));
            }
        }
        for (i, (host, allows)) in by_host.iter().enumerate() {
            rules.push_str(&format!("  egress_{i}:\n    endpoints:\n      - host: \"{host}\"\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules:\n"));
            for (m, p) in allows {
                rules.push_str(&format!("          - allow:\n              method: \"{m}\"\n              path: \"{p}\"\n"));
            }
            rules.push_str("    binaries:\n      - path: \"/**\"\n");
        }
        if rules.is_empty() {
            y.push_str("network_policies: {}\n");
        } else {
            y.push_str("network_policies:\n");
            y.push_str(&rules);
        }
        Ok(y)
    }

    /// Size-limited tmpfs for the work directory and `/tmp` (512 and 256 MiB, as in the Docker
    /// sandbox), so a task cannot fill the contributor's disk. Needs the gateway's
    /// `allow_driver_config = true`.
    pub fn driver_config_json() -> String {
        format!(
            r#"{{"docker":{{"mounts":[{{"type":"tmpfs","target":"{WORKDIR}","size_bytes":{},"mode":1023}},{{"type":"tmpfs","target":"/tmp","size_bytes":{},"mode":1023}}]}}}}"#,
            512u64 << 20,
            256u64 << 20
        )
    }

    fn exec_prefix(&self, name: &str) -> Vec<String> {
        let mut p = vec![];
        if !self.env.is_empty() {
            p.push("env".into());
            p.extend(self.env.iter().map(|(k, v)| format!("{k}={v}")));
        }
        p.push(self.bin.clone());
        if let Some(g) = &self.gateway {
            p.extend(["--gateway".into(), g.clone()]);
        }
        p.extend(["sandbox", "exec", "-n", name, "--no-login-shell", "--timeout", "0", "--"].map(String::from));
        p
    }
}

impl Sandbox for OpenShellSandbox {
    fn probe(&self) -> Result<()> {
        if let Some(g) = &self.managed
            && !g.healthy()
        {
            return Err(Error::Sandbox(format!("toto's OpenShell gateway is not answering: {}", g.log_tail())));
        }
        self.run(&["status"]).map(|_| ()).map_err(|e| Error::Sandbox(format!("no OpenShell gateway reachable ({e})")))
    }

    fn create(&self, task: &TaskManifest, profile: &SandboxProfile) -> Result<Workspace> {
        let env = self.environments.get(&task.project_id).ok_or_else(|| Error::Sandbox(format!("no approved environment for project `{}` (`toto projects add`)", task.project_id)))?;
        let egress = self.egress.get(&task.project_id).cloned().unwrap_or_default();
        if env.network && egress.is_empty() {
            // OpenShell grants destinations one by one; "any destination" is not offered.
            return Err(Error::Sandbox("this project's agent needs a network but declares no egress rules; the OpenShell backend only grants listed destinations".into()));
        }
        let name = Self::sandbox_name(&task.id);
        let _ = self.run(&["sandbox", "delete", &name]); // a leftover from a crash would block a retry
        std::fs::create_dir_all(&self.scratch)?;
        let policy = self.scratch.join(format!("{name}.policy.yaml"));
        let proxy_port = self.proxy.as_ref().and_then(|p| p.url.rsplit(':').next()?.parse().ok());
        std::fs::write(&policy, Self::policy_yaml(proxy_port, if env.network { &egress } else { &[] })?)?;
        let (cpu, mem, timeout) = (format!("{:.2}", profile.cpu_millis as f64 / 1000.0), format!("{}Mi", profile.memory_mb), profile.timeout_secs.to_string());
        let driver = Self::driver_config_json();
        self.run(&[
            "sandbox", "create", "--name", &name, "--from", &env.image, "--policy", &policy.to_string_lossy(),
            "--driver-config-json", &driver, "--cpu", &cpu, "--memory", &mem, "--label", "toto=task", "--detach", "--", "sleep", &timeout,
        ])
        .map_err(|e| match e.to_string().contains("allow_driver_config") {
            true => Error::Sandbox("the OpenShell gateway must allow driver config (`allow_driver_config = true` under [openshell.drivers.docker]) so toto can cap the task's disk use; toto's managed gateway does".into()),
            false => e,
        })?;
        let ws = Workspace { task_id: task.id.clone(), path: PathBuf::new(), exec_prefix: self.exec_prefix(&name), style: ExecStyle::OpenShell, workdir: WORKDIR.into(), proxy: self.proxy.clone().unwrap_or_default() };
        let out = exec_io(&ws, &["true"], None, Duration::from_secs(120), 4096)?;
        if !out.status.success() {
            let _ = self.run(&["sandbox", "delete", &name]);
            return Err(Error::Sandbox(format!("the sandbox did not start: {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        Ok(ws)
    }

    fn put_inputs(&self, ws: &Workspace, bundle: &[u8], max_bytes: u64) -> Result<()> {
        let records = crate::archive::from_bytes(bundle, crate::archive::Limits::new(max_bytes)).map_err(Error::Sandbox)?;
        // `sandbox upload` needs an ssh client on the host; exec stdin needs nothing, but takes at
        // most 4 MiB per call. So the bundle goes over in pieces, appended to a file, then unpacked.
        let fail = |what: &str, out: &std::process::Output| Error::Sandbox(format!("{what} (the image must provide `tar`): {}", String::from_utf8_lossy(&out.stderr).trim()));
        let t = Duration::from_secs(300);
        if bundle.len() <= STDIN_LIMIT {
            let out = exec_io(ws, &["tar", "-x", "-f", "-", "-C", &ws.workdir], Some(bundle), t, 64 * 1024)?;
            if !out.status.success() {
                return Err(fail("unpacking inputs failed", &out));
            }
        } else {
            let file = "/tmp/toto-inputs.tar";
            for (i, chunk) in bundle.chunks(STDIN_LIMIT).enumerate() {
                let redirect = if i == 0 { ">" } else { ">>" };
                let out = exec_io(ws, &["sh", "-c", &format!("cat {redirect} {file}")], Some(chunk), t, 4096)?;
                if !out.status.success() {
                    return Err(fail("sending inputs failed", &out));
                }
            }
            let out = exec_io(ws, &["sh", "-c", &format!("tar -x -f {file} -C \"$1\" && rm -f {file}"), "sh", &ws.workdir], None, t, 64 * 1024)?;
            if !out.status.success() {
                return Err(fail("unpacking inputs failed", &out));
            }
        }
        self.baselines.lock().unwrap().entry(ws.task_id.clone()).or_default().extend(crate::archive::baseline_of(&records));
        Ok(())
    }

    fn collect_outputs(&self, ws: &Workspace, max_bytes: u64) -> Result<Vec<u8>> {
        let base = self.baselines.lock().unwrap().get(&ws.task_id).cloned().unwrap_or_default();
        collect_via_exec(ws, &base, max_bytes)
    }

    fn destroy(&self, ws: Workspace) -> Result<()> {
        self.baselines.lock().unwrap().remove(&ws.task_id);
        let name = Self::sandbox_name(&ws.task_id);
        let _ = std::fs::remove_file(self.scratch.join(format!("{name}.policy.yaml")));
        let _ = self.run(&["sandbox", "delete", &name]);
        Ok(())
    }
}
