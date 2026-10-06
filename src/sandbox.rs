//! Sandbox manager (ADR 5: the task workspace lives inside the sandbox).

use crate::manifest::{SandboxProfile, TaskManifest};
use crate::{Error, Result};
use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Where the static relay binary appears inside a container.
pub const RELAY_PATH: &str = "/toto/relay";
/// Where the credential proxy's unix socket appears inside the container.
pub const PROXY_SOCKET_PATH: &str = "/toto/proxy.sock";
/// Loopback address the in-container relay serves; the agent's API base URL points here.
pub const PROXY_ADDR: &str = "127.0.0.1:8080";

/// An isolated workspace for one task. Dropping it must destroy the environment.
pub trait Sandbox: Send {
    /// Checks at daemon start that this backend works here (binary present, images pulled...).
    fn probe(&self) -> Result<()> {
        Ok(())
    }
    /// Creates an environment honouring `profile` and returns the host-visible workspace path.
    fn create(&self, task: &TaskManifest, profile: &SandboxProfile) -> Result<Workspace>;
    fn destroy(&self, ws: Workspace) -> Result<()>;

    /// Unpacks a verified input archive into the task workspace and records a baseline so the
    /// task's changes can be collected afterwards. Default: host-path workspaces.
    fn put_inputs(&self, ws: &Workspace, bundle: &[u8], max_bytes: u64) -> Result<()> {
        host_put_inputs(ws, bundle, max_bytes)
    }

    /// Archive (tar) of files changed, added or deleted since `put_inputs`, at most `max_bytes`
    /// of content.
    fn collect_outputs(&self, ws: &Workspace, max_bytes: u64) -> Result<Vec<u8>> {
        host_collect_outputs(ws, max_bytes)
    }
}

fn baseline_path(ws: &Workspace) -> Result<PathBuf> {
    let name = ws.path.file_name().ok_or_else(|| Error::Sandbox("this sandbox has no host workspace to carry inputs".into()))?;
    Ok(ws.path.with_file_name(format!("{}.baseline.json", name.to_string_lossy())))
}

fn host_put_inputs(ws: &Workspace, bundle: &[u8], max_bytes: u64) -> Result<()> {
    let records = crate::archive::from_bytes(bundle, crate::archive::Limits::new(max_bytes)).map_err(Error::Sandbox)?;
    crate::archive::unpack_to(&ws.path, &records).map_err(Error::Sandbox)?;
    let mut base: std::collections::BTreeMap<String, String> = std::fs::read(baseline_path(ws)?).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    base.extend(crate::archive::baseline_of(&records));
    std::fs::write(baseline_path(ws)?, serde_json::to_vec(&base)?)?;
    Ok(())
}

fn host_collect_outputs(ws: &Workspace, max_bytes: u64) -> Result<Vec<u8>> {
    let base = match std::fs::read(baseline_path(ws)?) {
        Ok(b) => serde_json::from_slice(&b)?,
        Err(_) => Default::default(),
    };
    let changes = crate::archive::changes_since(&ws.path, &base, crate::archive::Limits::new(max_bytes)).map_err(Error::Sandbox)?;
    crate::archive::to_bytes(&changes).map_err(Error::Sandbox)
}

impl<T: Sandbox + ?Sized> Sandbox for Box<T> {
    fn probe(&self) -> Result<()> {
        (**self).probe()
    }
    fn create(&self, task: &TaskManifest, profile: &SandboxProfile) -> Result<Workspace> {
        (**self).create(task, profile)
    }
    fn destroy(&self, ws: Workspace) -> Result<()> {
        (**self).destroy(ws)
    }
    fn put_inputs(&self, ws: &Workspace, bundle: &[u8], max_bytes: u64) -> Result<()> {
        (**self).put_inputs(ws, bundle, max_bytes)
    }
    fn collect_outputs(&self, ws: &Workspace, max_bytes: u64) -> Result<Vec<u8>> {
        (**self).collect_outputs(ws, max_bytes)
    }
}

#[derive(Debug)]
pub struct Workspace {
    pub task_id: String,
    /// Host-visible directory (only `DirSandbox`; empty for container sandboxes, which hold
    /// no host filesystem).
    pub path: PathBuf,
    /// Command prefix the harness uses to run a command *inside* the sandbox, e.g.
    /// `docker exec -i <container>`. Empty for `DirSandbox`.
    pub exec_prefix: Vec<String>,
}

/// **Not isolating.** A plain temp directory for the demo and tests; it enforces none of the
/// profile.
pub struct DirSandbox {
    pub root: PathBuf,
}

impl Sandbox for DirSandbox {
    fn create(&self, task: &TaskManifest, _profile: &SandboxProfile) -> Result<Workspace> {
        let path = self.root.join(&task.id);
        std::fs::create_dir_all(&path)?;
        Ok(Workspace { task_id: task.id.clone(), path, exec_prefix: vec![] })
    }

    fn destroy(&self, ws: Workspace) -> Result<()> {
        if let Ok(b) = baseline_path(&ws) {
            let _ = std::fs::remove_file(b);
        }
        std::fs::remove_dir_all(ws.path)?;
        Ok(())
    }
}

/// The approved environment a project's tasks run in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    /// Pinned image reference: `repo@sha256:...` or an image id.
    pub image: String,
    /// Tasks get the fenced network (the approved agent needs one).
    pub network: bool,
}

/// Hardened Docker/Podman sandbox: one throwaway container per task, in the project's approved image.
///
/// - no network (`--network none`) unless the approved agent needs one, and then only the fenced
///   bridge the contributor named (`netfence`); without one such tasks are refused (fail closed);
/// - read-only root, all capabilities dropped, `no-new-privileges`, non-root user;
/// - no host mounts: the workspace is a size-limited tmpfs inside the container;
/// - CPU, memory and pids limits from the profile;
/// - wall-clock limit: the container's PID 1 is `sleep <timeout>`, so it dies at the deadline.
///
/// Set `runtime` to `runsc` to run under gVisor.
pub struct DockerSandbox {
    /// `docker` or `podman`.
    pub bin: String,
    pub runtime: Option<String>,
    pub workspace_mb: u32,
    /// The approved environment per project id. A task from a project without one is refused.
    pub environments: std::collections::HashMap<String, Environment>,
    /// Static `toto-relay` binary mounted read-only at `RELAY_PATH`: the only host path a task
    /// container can see. Needed when `proxy_socket` is set.
    pub relay: Option<PathBuf>,
    /// Credential proxy socket (host side), bind-mounted at `PROXY_SOCKET_PATH`. When set, a
    /// loopback relay to it is started inside the container at `PROXY_ADDR`.
    pub proxy_socket: Option<PathBuf>,
    /// Seccomp profile file. `None` keeps Docker's default; toto's opt-in profile allows a nested
    /// bubblewrap (see `profiles/README.md`).
    pub seccomp_profile: Option<PathBuf>,
    /// Name of a fenced user-defined docker network (see `netfence`) for agents that need one.
    pub network: Option<String>,
    /// Content baselines of unpacked inputs, by task id (kept on the host, never in the container).
    baselines: std::sync::Mutex<std::collections::HashMap<String, std::collections::BTreeMap<String, String>>>,
}

impl DockerSandbox {
    pub fn new() -> Self {
        Self { bin: "docker".into(), runtime: None, workspace_mb: 512, environments: Default::default(), relay: None, proxy_socket: None, seccomp_profile: None, network: None, baselines: Default::default() }
    }

    pub fn container_name(task_id: &str) -> String {
        let safe: String = task_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
        format!("toto-{safe}")
    }

    pub fn environment_for(&self, project: &str) -> Result<&Environment> {
        self.environments.get(project).ok_or_else(|| Error::Sandbox(format!("no approved environment for project `{project}` (`toto projects add`)")))
    }

    /// The `run` argument list; pure so the hardening flags are unit-tested without a daemon.
    pub fn run_args(&self, task_id: &str, env: &Environment, p: &SandboxProfile) -> Result<Vec<String>> {
        let net = match (&self.network, env.network) {
            (_, false) => "none",
            (Some(name), true) => name.as_str(),
            (None, true) => return Err(Error::Sandbox("this project's agent needs a network but the sandbox has no fenced `network` configured (`toto net-setup`); refusing to run".into())),
        };
        let mut a: Vec<String> = [
            "run", "-d", "--rm", "--name", &Self::container_name(task_id),
            "--network", net, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", "65534:65534",
            "--pids-limit", "256", "--workdir", "/workspace",
            // A prebuilt snapshot may carry the devcontainer CLI's entrypoint; tasks never use it.
            "--entrypoint", "",
        ]
        .map(String::from)
        .into();
        a.extend([
            "--cpus".into(), format!("{:.2}", p.cpu_millis as f64 / 1000.0),
            "--memory".into(), format!("{}m", p.memory_mb),
            "--tmpfs".into(), format!("/workspace:rw,noexec,nosuid,mode=1777,size={}m", self.workspace_mb),
            "--tmpfs".into(), "/tmp:rw,nosuid,mode=1777,size=256m".into(),
        ]);
        if let Some(b) = &self.relay {
            a.extend(["--mount".into(), format!("type=bind,src={},dst={RELAY_PATH},readonly", b.display())]);
        }
        if let Some(profile) = &self.seccomp_profile {
            a.extend(["--security-opt".into(), format!("seccomp={}", profile.display())]);
        }
        if let Some(sock) = &self.proxy_socket {
            a.extend(["--mount".into(), format!("type=bind,src={},dst={PROXY_SOCKET_PATH}", sock.display())]);
        }
        if let Some(rt) = &self.runtime {
            a.extend(["--runtime".into(), rt.clone()]);
        }
        a.extend([env.image.clone(), "sleep".into(), p.timeout_secs.to_string()]);
        Ok(a)
    }

    fn docker(&self, args: &[String]) -> Result<std::process::Output> {
        let out = std::process::Command::new(&self.bin).args(args).output()?;
        if out.status.success() {
            Ok(out)
        } else {
            Err(Error::Sandbox(String::from_utf8_lossy(&out.stderr).trim().to_string()))
        }
    }

    /// Starts the loopback relay to the credential proxy inside the container and waits until it
    /// accepts connections.
    fn start_relay(&self, container: &str) -> Result<()> {
        if self.relay.is_none() {
            return Err(Error::Sandbox("the credential proxy needs the relay binary (`relay` in the sandbox config)".into()));
        }
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        self.docker(&s(&["exec", "-d", container, RELAY_PATH, "relay", PROXY_ADDR, PROXY_SOCKET_PATH]))?;
        for _ in 0..50 {
            if self.docker(&s(&["exec", container, RELAY_PATH, "probe", PROXY_ADDR])).is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(Error::Sandbox("the credential proxy relay did not start".into()))
    }

    /// The image must be present. A pulled image (`repo@digest`) that is missing is pulled again;
    /// one built here cannot be, so the project must be updated.
    fn ensure_image(&self, image: &str) -> Result<()> {
        if self.docker(&["image".into(), "inspect".into(), image.into()]).is_ok() {
            return Ok(());
        }
        if !image.contains('@') {
            return Err(Error::Sandbox(format!("approved image `{image}` is no longer on this machine; run `toto projects update`")));
        }
        self.docker(&["pull".into(), "-q".into(), image.into()]).map(|_| ()).map_err(|e| Error::Sandbox(format!("could not pull the approved image `{image}`: {e}")))
    }
}

impl Default for DockerSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox for DockerSandbox {
    fn probe(&self) -> Result<()> {
        self.docker(&["version".into(), "--format".into(), "{{.Server.Version}}".into()])
            .map_err(|e| Error::Sandbox(format!("{} daemon unreachable: {e}", self.bin)))?;
        if let Some(r) = &self.relay
            && !r.is_file()
        {
            return Err(Error::Sandbox(format!("relay binary {} not found", r.display())));
        }
        for env in self.environments.values() {
            self.ensure_image(&env.image)?;
            if env.network && self.network.is_none() {
                return Err(Error::Sandbox(format!("image `{}` needs a network but no fenced `network` is configured (`toto net-setup`)", env.image)));
            }
        }
        if let Some(net) = &self.network
            && let Some(env) = self.environments.values().next()
        {
            crate::netfence::verify(&self.bin, net, &env.image)?;
        }
        Ok(())
    }

    fn create(&self, task: &TaskManifest, profile: &SandboxProfile) -> Result<Workspace> {
        let env = self.environment_for(&task.project_id)?;
        self.ensure_image(&env.image)?;
        let args = self.run_args(&task.id, env, profile)?;
        let name = Self::container_name(&task.id);
        // A container left behind by a crash or an aborted run would block a retry of this task.
        let _ = self.docker(&["rm".into(), "-f".into(), name.clone()]);
        self.docker(&args)?;
        let exec_prefix = vec![self.bin.clone(), "exec".into(), "-i".into(), name.clone()];
        if self.proxy_socket.is_some() {
            self.start_relay(&name)?;
        }
        Ok(Workspace { task_id: task.id.clone(), path: PathBuf::new(), exec_prefix })
    }

    fn put_inputs(&self, ws: &Workspace, bundle: &[u8], max_bytes: u64) -> Result<()> {
        // Validate on the host first, so the tar the container extracts holds only regular files
        // and directories at safe relative paths.
        let records = crate::archive::from_bytes(bundle, crate::archive::Limits::new(max_bytes)).map_err(Error::Sandbox)?;
        let out = exec_io(ws, &["tar", "-x", "-f", "-", "-C", "/workspace"], Some(bundle), Duration::from_secs(300), 64 * 1024)?;
        if !out.status.success() {
            return Err(Error::Sandbox(format!("unpacking inputs failed (the image must provide `tar`): {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        self.baselines.lock().unwrap().entry(ws.task_id.clone()).or_default().extend(crate::archive::baseline_of(&records));
        Ok(())
    }

    fn collect_outputs(&self, ws: &Workspace, max_bytes: u64) -> Result<Vec<u8>> {
        use std::sync::{Arc, Mutex};
        let base = self.baselines.lock().unwrap().get(&ws.task_id).cloned().unwrap_or_default();
        let (prog, rest) = ws.exec_prefix.split_first().ok_or_else(|| Error::Sandbox("not a container workspace".into()))?;
        let mut child = Command::new(prog)
            .args(rest)
            .args(["tar", "-c", "-f", "-", "-C", "/workspace", "."])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (stdout, mut stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let err = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::take(&mut stderr, 1 << 16).read_to_string(&mut s);
            s
        });
        // Watchdog: a hung `tar` must not stall the runner.
        let child = Arc::new(Mutex::new(child));
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (wc, wd) = (child.clone(), done.clone());
        let watchdog = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(300);
            while !wd.load(std::sync::atomic::Ordering::Relaxed) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            if !wd.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = wc.lock().unwrap().kill();
            }
        });
        let limits = crate::archive::Limits::new(max_bytes);
        let parsed = crate::archive::changes_from_tar(stdout, &base, limits);
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = watchdog.join();
        let mut child = child.lock().unwrap();
        if parsed.is_err() {
            let _ = child.kill();
        }
        let status = child.wait()?;
        let stderr = err.join().unwrap_or_default();
        let changes = parsed.map_err(|e| Error::Sandbox(format!("collecting outputs failed: {e}")))?;
        if !status.success() {
            return Err(Error::Sandbox(format!("collecting outputs failed (the image must provide `tar`): {}", stderr.trim())));
        }
        crate::archive::to_bytes(&changes).map_err(Error::Sandbox)
    }

    fn destroy(&self, ws: Workspace) -> Result<()> {
        self.baselines.lock().unwrap().remove(&ws.task_id);
        // `--rm` removes it once stopped; `-t 0` kills immediately. Ignore "already gone".
        let _ = self.docker(&["stop".into(), "-t".into(), "0".into(), Self::container_name(&ws.task_id)]);
        Ok(())
    }
}

/// Runs `argv` inside the sandbox (prefixed by `ws.exec_prefix`) and kills it at `timeout`.
/// Harnesses use this so a hung tool can never stall the runner past its deadline.
pub fn exec(ws: &Workspace, argv: &[&str], timeout: Duration) -> Result<Output> {
    exec_io(ws, argv, None, timeout, usize::MAX)
}

/// Like `exec`, feeding `input` to stdin and keeping at most `max_out` bytes of stdout.
pub fn exec_io(ws: &Workspace, argv: &[&str], input: Option<&[u8]>, timeout: Duration, max_out: usize) -> Result<Output> {
    use std::io::{Read, Write};
    let (prog, args): (&str, Vec<&str>) = match ws.exec_prefix.split_first() {
        Some((p, rest)) => (p, rest.iter().map(String::as_str).chain(argv.iter().copied()).collect()),
        None => (argv[0], argv[1..].to_vec()),
    };
    let mut cmd = Command::new(prog);
    cmd.args(args).stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    if ws.exec_prefix.is_empty() && !ws.path.as_os_str().is_empty() {
        cmd.current_dir(&ws.path);
    }
    let mut child = cmd.spawn()?;
    let writer = input.map(|data| {
        let (mut stdin, data) = (child.stdin.take().unwrap(), data.to_vec());
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data); // closing stdin (drop) signals end of input
        })
    });
    let drain = |r: Box<dyn Read + Send>, cap: usize| {
        std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = r.take((cap as u64).saturating_add(1)).read_to_end(&mut b);
            b
        })
    };
    let (out, err) = (drain(Box::new(child.stdout.take().unwrap()), max_out), drain(Box::new(child.stderr.take().unwrap()), 1 << 20));
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Sandbox(format!("command timed out after {timeout:?}")));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if let Some(w) = writer {
        let _ = w.join();
    }
    let stdout = out.join().unwrap_or_default();
    if stdout.len() > max_out {
        return Err(Error::Sandbox(format!("output exceeds {max_out} bytes")));
    }
    Ok(Output { status, stdout, stderr: err.join().unwrap_or_default() })
}
