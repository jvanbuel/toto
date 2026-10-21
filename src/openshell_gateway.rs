//! The OpenShell gateway toto runs for itself (ADR 17): private to toto, started with the daemon,
//! stopped with it, and configured only by toto, so contributors never set up OpenShell.
//!
//! Everything lives under `<state_dir>/openshell/gateway`: its mTLS material (generated once),
//! its config, its database, its log, and the CLI's registration of it (an isolated
//! `XDG_CONFIG_HOME`, so the contributor's own OpenShell setup, if any, is never touched). It
//! listens on loopback only and runs exactly the images pinned in `openshell.lock.toml`.
//!
//! One gateway per state directory per process: a daemon reload builds a new runner while the
//! old one drains, and both use the same gateway.

use crate::openshell_pin::{Bins, Images};
use crate::{Error, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

/// The CLI's name for toto's gateway, inside toto's own CLI config.
pub const NAME: &str = "toto";

/// Default port; the health endpoint listens on the next one.
pub const DEFAULT_PORT: u16 = 17717;

/// How the gateway reaches the internet when the host must go through an HTTP proxy. The
/// supervisor applies it to sandbox egress; toto's credential proxy on the host is always
/// reached directly.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpstreamProxy {
    /// `http://host:port`.
    pub url: String,
    /// CA bundle of a TLS-intercepting proxy.
    #[serde(default)]
    pub ca_bundle: Option<PathBuf>,
    /// CONNECT by hostname instead of by resolved IP (proxies that allow by name).
    #[serde(default)]
    pub connect_by_hostname: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Labels this gateway's containers and volumes. A gateway cleans up whatever carries its
    /// label at startup, so each gateway on a Docker host needs its own (`label_for`).
    pub label: String,
    pub port: u16,
    pub images: Images,
    pub upstream_proxy: Option<UpstreamProxy>,
}

impl Settings {
    /// The gateway's config file. Pure, so it is unit-tested.
    pub fn gateway_toml(&self) -> String {
        let q = |s: &str| toml::Value::String(s.into()).to_string();
        let mut t = format!(
            "[openshell]\nversion = 2\n\n\
             [openshell.gateway]\nname = {name}\nbind_address = \"127.0.0.1:{port}\"\nhealth_bind_address = \"127.0.0.1:{health}\"\ncompute_driver = \"docker\"\nlog_level = \"info\"\n\n\
             [openshell.drivers.docker]\nsupervisor_image = {sup}\nsandbox_runtime_image = {rt}\nimage_pull_policy = \"if_not_present\"\nsandbox_label = {label}\n\
             # toto caps each task's /work and /tmp with tmpfs mounts.\nallow_driver_config = true\n",
            name = q(NAME),
            port = self.port,
            health = self.port + 1,
            sup = q(&self.images.supervisor),
            rt = q(&self.images.sandbox_runtime),
            label = q(&self.label),
        );
        if let Some(p) = &self.upstream_proxy {
            t.push_str(&format!("https_proxy = {}\n", q(&p.url)));
            // Sandboxes reach toto's credential proxy on the host directly.
            t.push_str(&format!("no_proxy = \"{},localhost,127.0.0.1\"\n", crate::openshell::HOST_ALIAS));
            if let Some(ca) = &p.ca_bundle {
                t.push_str(&format!("proxy_ca_bundle = {}\n", q(&ca.to_string_lossy())));
            }
            if p.connect_by_hostname {
                t.push_str("proxy_connect_by_hostname = true\n");
            }
        }
        t
    }
}

/// The sandbox label for the gateway of `state_dir`: distinct per toto installation, and never
/// OpenShell's own `default`, so neither cleans up the other's sandboxes.
pub fn label_for(state_dir: &Path) -> String {
    let abs = std::path::absolute(state_dir).unwrap_or_else(|_| state_dir.to_path_buf());
    format!("toto-{}", &crate::archive::sha256_hex(abs.to_string_lossy().as_bytes())[..12])
}

/// A running gateway. Dropping the last handle stops it; the sandboxes it ran go with it.
pub struct ManagedGateway {
    pub dir: PathBuf,
    pub settings: Settings,
    pub bins: Bins,
    child: Mutex<Option<Child>>,
}

static RUNNING: Mutex<Option<HashMap<PathBuf, Weak<ManagedGateway>>>> = Mutex::new(None);

impl ManagedGateway {
    /// The gateway for `state_dir`: the one already running in this process if its settings are
    /// unchanged, else a freshly started one.
    pub fn shared(bins: &Bins, state_dir: &Path, settings: &Settings) -> Result<Arc<Self>> {
        let dir = state_dir.join("openshell").join("gateway");
        let mut running = RUNNING.lock().unwrap();
        let map = running.get_or_insert_with(HashMap::new);
        if let Some(g) = map.get(&dir).and_then(Weak::upgrade) {
            if g.settings == *settings && g.bins == *bins && g.healthy() {
                return Ok(g);
            }
            return Err(Error::Sandbox("the OpenShell settings changed; restart the daemon to apply them".into()));
        }
        // Another toto process (the daemon, while `toto doctor` runs) owns a running gateway:
        // use it, leave it running.
        if owner_alive(&dir) && health(settings.port + 1) {
            let g = Arc::new(Self { dir: dir.clone(), settings: settings.clone(), bins: bins.clone(), child: Mutex::new(None) });
            map.insert(dir, Arc::downgrade(&g));
            return Ok(g);
        }
        let g = Arc::new(Self::start(bins, &dir, settings)?);
        map.insert(dir, Arc::downgrade(&g));
        Ok(g)
    }

    fn start(bins: &Bins, dir: &Path, settings: &Settings) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        stop_leftover(dir);
        let tls = dir.join("tls");
        if !tls.join("client").join("tls.key").is_file() {
            let out = Command::new(&bins.gateway)
                .args(["generate-certs", "--output-dir"])
                .arg(&tls)
                .args(["--server-san", "127.0.0.1", "--server-san", "localhost", "--server-san", crate::openshell::HOST_ALIAS])
                .output()?;
            if !out.status.success() {
                return Err(Error::Sandbox(format!("openshell-gateway generate-certs: {}", String::from_utf8_lossy(&out.stderr).trim())));
            }
        }
        let config = dir.join("gateway.toml");
        std::fs::write(&config, settings.gateway_toml())?;
        let log = std::fs::File::create(dir.join("gateway.log"))?;
        let child = Command::new(&bins.gateway)
            .arg("--config")
            .arg(&config)
            .arg("--db-url")
            .arg(format!("sqlite:{}", dir.join("gateway.db").display()))
            .envs(Self::env_for(dir))
            .env_remove("OPENSHELL_GATEWAY_CONFIG")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .map_err(|e| Error::Sandbox(format!("starting {}: {e}", bins.gateway.display())))?;
        std::fs::write(dir.join("gateway.pid"), child.id().to_string())?;
        std::fs::write(dir.join("owner.pid"), std::process::id().to_string())?;
        let g = Self { dir: dir.to_path_buf(), settings: settings.clone(), bins: bins.clone(), child: Mutex::new(Some(child)) };
        g.wait_healthy(Duration::from_secs(60))?;
        g.register()?;
        Ok(g)
    }

    /// The environment every `openshell` CLI call and the gateway itself run with.
    fn env_for(dir: &Path) -> Vec<(String, String)> {
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        vec![
            ("OPENSHELL_LOCAL_TLS_DIR".into(), s(dir.join("tls"))),
            ("XDG_CONFIG_HOME".into(), s(dir.join("cli"))),
            ("XDG_STATE_HOME".into(), s(dir.join("state"))),
        ]
    }

    pub fn cli_env(&self) -> Vec<(String, String)> {
        Self::env_for(&self.dir)
    }

    fn register(&self) -> Result<()> {
        let _ = std::fs::remove_dir_all(self.dir.join("cli"));
        let out = Command::new(&self.bins.cli)
            .args(["gateway", "add", &format!("https://127.0.0.1:{}", self.settings.port), "--local", "--name", NAME])
            .envs(self.cli_env())
            .stdin(Stdio::null())
            .output()?;
        if !out.status.success() {
            return Err(Error::Sandbox(format!("registering toto's OpenShell gateway: {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        Ok(())
    }

    fn wait_healthy(&self, limit: Duration) -> Result<()> {
        let start = Instant::now();
        while start.elapsed() < limit {
            if let Some(status) = self.child.lock().unwrap().as_mut().and_then(|c| c.try_wait().ok().flatten()) {
                return Err(Error::Sandbox(format!("the OpenShell gateway exited ({status}): {}", self.log_tail())));
            }
            if self.healthy() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Err(Error::Sandbox(format!("the OpenShell gateway did not become healthy within {}s: {}", limit.as_secs(), self.log_tail())))
    }

    /// Whether the gateway answers its health endpoint.
    pub fn healthy(&self) -> bool {
        health(self.settings.port + 1)
    }

    /// The last lines of the gateway's log, for error messages.
    pub fn log_tail(&self) -> String {
        let log = std::fs::read_to_string(self.dir.join("gateway.log")).unwrap_or_default();
        let lines: Vec<&str> = log.lines().rev().take(5).collect();
        lines.into_iter().rev().collect::<Vec<_>>().join(" | ")
    }
}

impl Drop for ManagedGateway {
    fn drop(&mut self) {
        let Some(mut c) = self.child.lock().unwrap().take() else { return }; // not ours to stop
        let _ = Command::new("kill").arg(c.id().to_string()).status(); // SIGTERM: a clean shutdown
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) && c.try_wait().ok().flatten().is_none() {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = c.kill();
        let _ = c.wait();
        let _ = std::fs::remove_file(self.dir.join("gateway.pid"));
        let _ = std::fs::remove_file(self.dir.join("owner.pid"));
    }
}

/// Whether the toto process that started the gateway of `dir` is still running.
fn owner_alive(dir: &Path) -> bool {
    let Some(pid) = std::fs::read_to_string(dir.join("owner.pid")).ok().and_then(|s| s.trim().parse::<u32>().ok()) else { return false };
    pid != std::process::id() && Command::new("kill").args(["-0", &pid.to_string()]).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

/// `GET /healthz` on the health port answers 200.
pub fn health(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    if s.write_all(b"GET /healthz HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").is_err() {
        return false;
    }
    let mut head = [0u8; 12];
    s.read_exact(&mut head).is_ok() && head.starts_with(b"HTTP/1.") && &head[9..12] == b"200"
}

/// Stops a gateway a crashed toto left running, so its port is free. Only a process that is an
/// OpenShell gateway is stopped: a pid file can outlive its process and the pid be reused.
fn stop_leftover(dir: &Path) {
    let Some(pid) = std::fs::read_to_string(dir.join("gateway.pid")).ok().and_then(|s| s.trim().parse::<u32>().ok()) else { return };
    let comm = Command::new("ps").args(["-p", &pid.to_string(), "-o", "comm="]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    if comm.contains("openshell-gat") {
        let _ = Command::new("kill").arg(pid.to_string()).status();
        std::thread::sleep(Duration::from_secs(1));
    }
    let _ = std::fs::remove_file(dir.join("gateway.pid"));
}
