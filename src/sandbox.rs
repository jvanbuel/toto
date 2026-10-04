//! Sandbox manager (ADR 5: the task workspace lives inside the sandbox).

use crate::manifest::{SandboxProfile, TaskManifest};
use crate::{Error, Result};
use std::path::PathBuf;
use std::io::Read as _;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Where the MCP exec bridge appears inside a container sandbox.
pub const BRIDGE_PATH: &str = "/toto/mcp-exec";
/// Where the credential proxy's unix socket and the agent binary appear inside the container.
pub const PROXY_SOCKET_PATH: &str = "/toto/proxy.sock";
pub const AGENT_DIR: &str = "/toto/agent";
/// Loopback address the in-container relay serves; the agent's API base URL points here.
pub const PROXY_ADDR: &str = "127.0.0.1:8080";

/// An isolated workspace for one task. Dropping it must destroy the environment.
pub trait Sandbox: Send {
    /// Checks at daemon start that this backend works here (binary present, image pulled...).
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

    /// Archive (toto format) of files changed, added or deleted since `put_inputs`, at most
    /// `max_bytes` of content.
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
    // Merge with any earlier baseline (inputs, then context).
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

impl Workspace {
    /// Command that starts the MCP exec bridge inside this sandbox (container sandboxes with a
    /// bridge only). The runner generates it; projects can never influence it.
    pub fn bridge_argv(&self) -> Option<Vec<String>> {
        let mut v = self.exec_prefix.clone();
        (self.bridge && !v.is_empty()).then(|| {
            v.push(BRIDGE_PATH.into());
            v
        })
    }
}

#[derive(Debug)]
pub struct Workspace {
    pub task_id: String,
    /// Host-visible directory (only `DirSandbox`; empty for container sandboxes, which hold
    /// no host filesystem).
    pub path: PathBuf,
    /// Command prefix the harness uses to run a command *inside* the sandbox (ADR 5), e.g.
    /// `docker exec -i <container> <cmd>`. Empty for `DirSandbox`.
    pub exec_prefix: Vec<String>,
    /// True when the bridge binary is mounted at `BRIDGE_PATH`.
    pub bridge: bool,
}

/// **Not isolating.** A plain temp directory for the spike and tests; it enforces none of the
/// profile. The Docker/microVM implementation (milestone 1) replaces it for real use.
pub struct DirSandbox {
    pub root: PathBuf,
}

impl Sandbox for DirSandbox {
    fn create(&self, task: &TaskManifest, _profile: &SandboxProfile) -> Result<Workspace> {
        let path = self.root.join(&task.id);
        std::fs::create_dir_all(&path)?;
        Ok(Workspace { task_id: task.id.clone(), path, exec_prefix: vec![], bridge: false })
    }

    fn destroy(&self, ws: Workspace) -> Result<()> {
        if let Ok(b) = baseline_path(&ws) {
            let _ = std::fs::remove_file(b);
        }
        std::fs::remove_dir_all(ws.path)?;
        Ok(())
    }
}

/// Hardened Docker/Podman sandbox: one throwaway container per task.
///
/// - no network (`--network none`); manifests asking for an allowlist are refused until an
///   egress proxy exists, so the sandbox fails closed;
/// - read-only root, all capabilities dropped, `no-new-privileges`, non-root user;
/// - no host mounts: the workspace is a size-limited tmpfs inside the container;
/// - CPU, memory and pids limits from the profile;
/// - wall-clock limit: the container's PID 1 is `sleep <timeout>`, so it dies at the deadline.
///
/// Set `runtime` to `runsc` to run under gVisor.
pub struct DockerSandbox {
    /// `docker` or `podman`.
    pub bin: String,
    pub image: String,
    pub runtime: Option<String>,
    pub workspace_mb: u32,
    /// Static `toto-mcp-exec` binary to mount read-only at `BRIDGE_PATH`: the only host path a
    /// task container can see.
    pub bridge: Option<PathBuf>,
    /// Credential proxy socket (host side), bind-mounted at `PROXY_SOCKET_PATH`. When set, a
    /// loopback relay to it is started inside the container at `PROXY_ADDR` (ADR 12).
    pub proxy_socket: Option<PathBuf>,
    /// Agent CLI files mounted read-only under `AGENT_DIR`, each under its own file name. The
    /// first is the executable; companions (e.g. Codex's `codex-code-mode-host`) must sit next to it.
    pub agent_files: Vec<PathBuf>,
    /// Content baselines of unpacked inputs, by task id (kept on the host, never in the container).
    baselines: std::sync::Mutex<std::collections::HashMap<String, std::collections::BTreeMap<String, String>>>,
}

impl DockerSandbox {
    pub fn new(image: impl Into<String>) -> Self {
        Self { bin: "docker".into(), image: image.into(), runtime: None, workspace_mb: 512, bridge: None, proxy_socket: None, agent_files: vec![], baselines: Default::default() }
    }

    pub fn container_name(task_id: &str) -> String {
        let safe: String = task_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
        format!("toto-{safe}")
    }

    /// The `run` argument list; pure so the hardening flags are unit-tested without a daemon.
    pub fn run_args(&self, task_id: &str, p: &SandboxProfile) -> Result<Vec<String>> {
        if !p.network_allowlist.is_empty() {
            return Err(Error::Sandbox("network allowlists are not supported yet; refusing to run".into()));
        }
        let mut a: Vec<String> = [
            "run", "-d", "--rm", "--name", &Self::container_name(task_id),
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", "65534:65534",
            "--pids-limit", "256", "--workdir", "/workspace",
        ]
        .map(String::from)
        .into();
        a.extend([
            "--cpus".into(), format!("{:.2}", p.cpu_millis as f64 / 1000.0),
            "--memory".into(), format!("{}m", p.memory_mb),
            "--tmpfs".into(), format!("/workspace:rw,noexec,nosuid,mode=1777,size={}m", self.workspace_mb),
            "--tmpfs".into(), "/tmp:rw,noexec,nosuid,mode=1777,size=64m".into(),
        ]);
        if let Some(b) = &self.bridge {
            a.extend(["--mount".into(), format!("type=bind,src={},dst={BRIDGE_PATH},readonly", b.display())]);
        }
        if let Some(sock) = &self.proxy_socket {
            a.extend(["--mount".into(), format!("type=bind,src={},dst={PROXY_SOCKET_PATH}", sock.display())]);
        }
        for f in &self.agent_files {
            a.extend(["--mount".into(), format!("type=bind,src={},dst={AGENT_DIR}/{},readonly", f.display(), f.file_name().unwrap_or_default().to_string_lossy())]);
        }
        if let Some(rt) = &self.runtime {
            a.extend(["--runtime".into(), rt.clone()]);
        }
        a.extend([self.image.clone(), "sleep".into(), p.timeout_secs.to_string()]);
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
}

impl DockerSandbox {
    /// Path of the agent executable inside the container, if agent files are configured.
    pub fn agent_exe(&self) -> Option<String> {
        self.agent_files.first().map(|f| format!("{AGENT_DIR}/{}", f.file_name().unwrap_or_default().to_string_lossy()))
    }

    /// Starts the loopback relay to the credential proxy inside the container and waits until it
    /// accepts connections. Needs the bridge binary (which provides `relay` and `probe`).
    fn start_relay(&self, container: &str) -> Result<()> {
        if self.bridge.is_none() {
            return Err(Error::Sandbox("the credential proxy relay needs the bridge binary".into()));
        }
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        self.docker(&s(&["exec", "-d", container, BRIDGE_PATH, "relay", PROXY_ADDR, PROXY_SOCKET_PATH]))?;
        for _ in 0..50 {
            if self.docker(&s(&["exec", container, BRIDGE_PATH, "probe", PROXY_ADDR])).is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(Error::Sandbox("the credential proxy relay did not start".into()))
    }
}

impl Sandbox for DockerSandbox {
    fn probe(&self) -> Result<()> {
        self.docker(&["version".into(), "--format".into(), "{{.Server.Version}}".into()])
            .map_err(|e| Error::Sandbox(format!("{} daemon unreachable: {e}", self.bin)))?;
        self.docker(&["image".into(), "inspect".into(), self.image.clone()])
            .map_err(|_| Error::Sandbox(format!("image `{}` not present; run `{} pull {}`", self.image, self.bin, self.image)))?;
        if let Some(exe) = self.agent_exe() {
            // The mounted agent must run in this image (the Claude CLI is a glibc binary: Alpine/musl images will not do).
            let mut args: Vec<String> = ["run", "--rm", "--network", "none"].map(String::from).into();
            for f in &self.agent_files {
                args.extend(["--mount".into(), format!("type=bind,src={},dst={AGENT_DIR}/{},readonly", f.display(), f.file_name().unwrap_or_default().to_string_lossy())]);
            }
            args.extend([self.image.clone(), exe, "--version".into()]);
            self.docker(&args)
                .map_err(|e| Error::Sandbox(format!("the agent binary does not run in image `{}` (it needs a glibc-based image such as debian or ubuntu): {e}", self.image)))?;
        }
        Ok(())
    }

    fn create(&self, task: &TaskManifest, profile: &SandboxProfile) -> Result<Workspace> {
        let args = self.run_args(&task.id, profile)?;
        let name = Self::container_name(&task.id);
        // A container left behind by a crash or an aborted run would block a retry of this task.
        let _ = self.docker(&["rm".into(), "-f".into(), name.clone()]);
        self.docker(&args)?;
        let exec_prefix = vec![self.bin.clone(), "exec".into(), "-i".into(), name.clone()];
        if self.proxy_socket.is_some() {
            self.start_relay(&name)?;
        }
        Ok(Workspace { task_id: task.id.clone(), path: PathBuf::new(), exec_prefix, bridge: self.bridge.is_some() })
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

/// bubblewrap sandbox (Linux): no daemon or image needed. Each exec is a fresh `bwrap` with
/// an empty root (read-only `/usr`, `/bin`, `/lib*`), no network, a fresh pid/ipc/uts/user
/// namespace, a cleared environment and a single writable scratch directory at `/workspace`.
///
/// Limits are weaker than a container: `prlimit` bounds processes, CPU seconds and data
/// segment size (an approximation of the memory limit); there is no pids/cgroup accounting.
pub struct BwrapSandbox {
    pub bin: String,
    /// Host directory holding per-task scratch dirs; the only host path a task can touch.
    pub root: PathBuf,
}

impl BwrapSandbox {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { bin: "bwrap".into(), root: root.into() }
    }

    /// Everything up to the user command; pure apart from reading the host's `/bin` layout.
    pub fn prefix(&self, host_dir: &std::path::Path, p: &SandboxProfile) -> Result<Vec<String>> {
        if !p.network_allowlist.is_empty() {
            return Err(Error::Sandbox("network allowlists are not supported yet; refusing to run".into()));
        }
        let mut a: Vec<String> = [
            &self.bin[..], "--unshare-all", "--die-with-parent", "--new-session", "--clearenv", "--cap-drop", "ALL",
            "--uid", "65534", "--gid", "65534", "--ro-bind", "/usr", "/usr",
        ]
        .map(String::from)
        .into();
        for d in ["bin", "sbin", "lib", "lib64"] {
            let host = PathBuf::from("/").join(d);
            match std::fs::read_link(&host) {
                Ok(target) => a.extend(["--symlink".into(), target.to_string_lossy().into(), format!("/{d}")]),
                Err(_) if host.is_dir() => a.extend(["--ro-bind".into(), format!("/{d}"), format!("/{d}")]),
                Err(_) => {}
            }
        }
        a.extend(["--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"].map(String::from));
        a.extend(["--bind".into(), host_dir.to_string_lossy().into(), "/workspace".into(), "--chdir".into(), "/workspace".into()]);
        a.extend(["--setenv", "HOME", "/workspace", "--setenv", "PATH", "/usr/bin:/bin"].map(String::from));
        a.extend([
            "prlimit".into(), "--nproc=256".into(), format!("--cpu={}", p.timeout_secs),
            format!("--data={}", p.memory_mb as u64 * 1024 * 1024),
        ]);
        Ok(a)
    }
}

impl Sandbox for BwrapSandbox {
    fn probe(&self) -> Result<()> {
        let dir = self.root.join(".probe");
        std::fs::create_dir_all(&dir)?;
        let ws = Workspace { task_id: "probe".into(), path: dir.clone(), exec_prefix: self.prefix(&dir, &SandboxProfile::default())?, bridge: false };
        let out = exec(&ws, &["true"], Duration::from_secs(10)).map_err(|e| Error::Sandbox(format!("bwrap unusable: {e}")))?;
        let _ = std::fs::remove_dir_all(dir);
        if out.status.success() {
            Ok(())
        } else {
            Err(Error::Sandbox(format!("bwrap probe failed: {}", String::from_utf8_lossy(&out.stderr).trim())))
        }
    }

    fn create(&self, task: &TaskManifest, profile: &SandboxProfile) -> Result<Workspace> {
        let path = self.root.join(DockerSandbox::container_name(&task.id));
        std::fs::create_dir_all(&path)?;
        let exec_prefix = self.prefix(&path, profile)?;
        Ok(Workspace { task_id: task.id.clone(), path, exec_prefix, bridge: false })
    }

    fn destroy(&self, ws: Workspace) -> Result<()> {
        if let Ok(b) = baseline_path(&ws) {
            let _ = std::fs::remove_file(b);
        }
        let _ = std::fs::remove_dir_all(ws.path);
        Ok(())
    }
}
