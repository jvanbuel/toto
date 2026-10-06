//! Runner side of the in-container relay (`relay/toto-relay.py`).
//!
//! The container runs the script over `docker exec -i`; this end demultiplexes the frames it
//! writes on stdout into one connection to the credential proxy's unix socket per loopback
//! connection in the container, and multiplexes the proxy's replies back on stdin. Nothing is
//! mounted and the container needs no network, so this works on Docker Desktop (macOS, Windows)
//! and Podman machine as well as on Linux.

use crate::{Error, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The script, embedded so the runner needs no file next to it.
pub const SCRIPT: &str = include_str!("../relay/toto-relay.py");
/// Where the script is written inside the container (its `/tmp` is a tmpfs of the task).
pub const SCRIPT_PATH: &str = "/tmp/toto-relay.py";

const OPEN: u8 = 1;
const DATA: u8 = 2;
const CLOSE: u8 = 3;
const READY: u8 = 4;
const HEADER: usize = 9;

type Conns = Arc<Mutex<HashMap<u32, UnixStream>>>;
type Stdin = Arc<Mutex<ChildStdin>>;

/// A running relay for one container. Dropping it ends the exec stream, which ends the script.
#[derive(Debug)]
pub struct RelayLink {
    child: Child,
}

impl RelayLink {
    /// Starts `prefix + [python3, script, listen]` with piped stdio and waits until the script
    /// reports it is listening. `prefix` is the container exec prefix (empty to run on the host,
    /// for tests).
    pub fn start(prefix: &[String], script: &str, listen: &str, proxy_socket: &Path) -> Result<Self> {
        let mut argv: Vec<&str> = prefix.iter().map(String::as_str).collect();
        argv.extend(["python3", script, listen]);
        let (prog, args) = argv.split_first().ok_or_else(|| Error::Sandbox("empty relay command".into()))?;
        let mut child = Command::new(prog).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        let stdin: Stdin = Arc::new(Mutex::new(child.stdin.take().unwrap()));
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let err = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.take(1 << 16).read_to_string(&mut s);
            s
        });
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let (sock, conns): (std::path::PathBuf, Conns) = (proxy_socket.to_path_buf(), Default::default());
        std::thread::spawn(move || demux(stdout, stdin, conns, &sock, ready_tx));
        match ready_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(()) => Ok(Self { child }),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let e = err.join().unwrap_or_default();
                Err(Error::Sandbox(format!("the credential relay did not start in the container (the image must provide `python3`, as Omnigent needs): {}", e.trim())))
            }
        }
    }
}

impl Drop for RelayLink {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn frame(stdin: &Stdin, id: u32, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(HEADER + payload.len());
    buf.extend_from_slice(&id.to_be_bytes());
    buf.push(kind);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    let mut w = stdin.lock().unwrap();
    w.write_all(&buf)?;
    w.flush()
}

fn demux(mut stdout: impl Read, stdin: Stdin, conns: Conns, sock: &Path, ready: std::sync::mpsc::Sender<()>) {
    let mut hdr = [0u8; HEADER];
    loop {
        if stdout.read_exact(&mut hdr).is_err() {
            break;
        }
        let id = u32::from_be_bytes(hdr[..4].try_into().unwrap());
        let kind = hdr[4];
        let len = u32::from_be_bytes(hdr[5..].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; len];
        if stdout.read_exact(&mut payload).is_err() {
            break;
        }
        match kind {
            READY => {
                let _ = ready.send(());
            }
            OPEN => {
                let Ok(up) = UnixStream::connect(sock) else {
                    let _ = frame(&stdin, id, CLOSE, &[]);
                    continue;
                };
                let Ok(reader) = up.try_clone() else { continue };
                conns.lock().unwrap().insert(id, up);
                let (stdin, conns) = (stdin.clone(), conns.clone());
                std::thread::spawn(move || pump(id, reader, stdin, conns));
            }
            DATA => {
                let failed = match conns.lock().unwrap().get_mut(&id) {
                    Some(up) => up.write_all(&payload).is_err(),
                    None => false,
                };
                if failed {
                    close(&conns, id);
                }
            }
            CLOSE => close(&conns, id),
            _ => {}
        }
    }
    // The stream is gone (container stopped or exec ended): drop every connection.
    for (_, up) in conns.lock().unwrap().drain() {
        let _ = up.shutdown(std::net::Shutdown::Both);
    }
}

/// Proxy to container, for one connection.
fn pump(id: u32, mut up: UnixStream, stdin: Stdin, conns: Conns) {
    let mut buf = vec![0u8; 1 << 16];
    loop {
        match up.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if frame(&stdin, id, DATA, &buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = frame(&stdin, id, CLOSE, &[]);
    close(&conns, id);
}

fn close(conns: &Conns, id: u32) {
    if let Some(up) = conns.lock().unwrap().remove(&id) {
        let _ = up.shutdown(std::net::Shutdown::Both);
    }
}
