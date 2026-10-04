//! Keeps a task container's network away from the contributor's own networks (ADR 12).
//!
//! The container may get a network only when the contributor opts in (`network` in the docker sandbox
//! config names a user-defined bridge). That bridge must be fenced: no route to private ranges, other
//! containers or the host itself. This module generates the firewall script (`toto net-setup`) and
//! verifies the result by behaviour, so the daemon refuses to run network tasks on an unfenced bridge.
//! The fence is host policy about *where* a container may go; it says nothing about *what* a task
//! may fetch, which stays the project's egress rules inside the container.

use crate::{Error, Result};
use std::net::TcpListener;
use std::process::Command;

/// Destinations a task container must never reach: RFC 1918, link-local (cloud metadata), CGNAT.
pub const PRIVATE_RANGES: [&str; 5] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"];

pub const DEFAULT_NETWORK: &str = "toto-egress";
pub const DEFAULT_SUBNET: &str = "172.30.0.0/24";

/// Non-loopback nameservers from a resolv.conf; the fence lets DNS through to these.
pub fn resolvers(resolv_conf: &str) -> Vec<String> {
    resolv_conf
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .map(|r| r.trim().to_string())
        .filter(|r| r.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| !ip.is_loopback()))
        .collect()
}

/// Shell script that creates the network (if missing) and installs the fence idempotently.
/// Rules live in `DOCKER-USER` (container to elsewhere) and `INPUT` (container to this host).
pub fn script(bin: &str, network: &str, subnet: &str, resolvers: &[String]) -> String {
    let mut s = String::from("set -e\n");
    s += &format!("{bin} network inspect {network} >/dev/null 2>&1 || {bin} network create --subnet {subnet} {network}\n");
    s += "iptables -N DOCKER-USER 2>/dev/null || true\n";
    let mut rule = |chain: &str, spec: &str| {
        s += &format!("iptables -C {chain} {spec} 2>/dev/null || iptables -I {chain} {spec}\n");
    };
    for r in PRIVATE_RANGES {
        rule("DOCKER-USER", &format!("-s {subnet} -d {r} -j DROP"));
    }
    rule("INPUT", &format!("-s {subnet} -j DROP"));
    for r in resolvers {
        for proto in ["udp", "tcp"] {
            rule("DOCKER-USER", &format!("-s {subnet} -d {r} -p {proto} --dport 53 -j ACCEPT"));
        }
    }
    s
}

/// Shell script that removes the fence rules and the network (`toto net-setup --remove`).
pub fn teardown_script(bin: &str, network: &str, subnet: &str, resolvers: &[String]) -> String {
    let mut s = String::new();
    let mut rule = |chain: &str, spec: &str| s += &format!("while iptables -D {chain} {spec} 2>/dev/null; do :; done\n");
    for r in PRIVATE_RANGES {
        rule("DOCKER-USER", &format!("-s {subnet} -d {r} -j DROP"));
    }
    rule("INPUT", &format!("-s {subnet} -j DROP"));
    for r in resolvers {
        for proto in ["udp", "tcp"] {
            rule("DOCKER-USER", &format!("-s {subnet} -d {r} -p {proto} --dport 53 -j ACCEPT"));
        }
    }
    s += &format!("{bin} network rm {network} >/dev/null 2>&1 || true\n");
    s
}

fn out(bin: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(bin).args(args).output()?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        Err(Error::Sandbox(String::from_utf8_lossy(&o.stderr).trim().to_string()))
    }
}

/// Checks by behaviour that a container on `network` cannot reach a service on this host: a listener
/// is opened on all host interfaces and a throwaway container tries to connect to the network's
/// gateway address. Refuses (an `Err`) when the connection succeeds or when the check cannot run.
pub fn verify(bin: &str, network: &str, image: &str) -> Result<()> {
    let gateway = out(bin, &["network", "inspect", network, "--format", "{{(index .IPAM.Config 0).Gateway}}"])
        .map_err(|e| Error::Sandbox(format!("network `{network}` not found ({e}); run `toto net-setup --apply`")))?;
    let listener = TcpListener::bind("0.0.0.0:0")?;
    let port = listener.local_addr()?.port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    listener.set_nonblocking(true)?;
    let seen = accepted.clone();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped = stop.clone();
    let watcher = std::thread::spawn(move || {
        while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
            if listener.accept().is_ok() {
                seen.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
    let probe = format!(
        "if command -v python3 >/dev/null; then python3 -c \"import socket;s=socket.socket();s.settimeout(3);s.connect(('{gateway}',{port}))\"; \
         elif command -v nc >/dev/null; then nc -w 3 -z {gateway} {port}; \
         elif command -v bash >/dev/null; then timeout 3 bash -c 'exec 3<>/dev/tcp/{gateway}/{port}'; \
         else exit 99; fi"
    );
    let run = Command::new(bin).args(["run", "--rm", "--network", network, image, "sh", "-c", &probe]).output();
    std::thread::sleep(std::time::Duration::from_millis(150));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = watcher.join();
    let status = run?.status.code();
    if accepted.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(Error::Sandbox(format!("network `{network}` is not fenced: a container reached this host at {gateway}:{port}; run `toto net-setup --apply`")));
    }
    if status == Some(99) {
        return Err(Error::Sandbox(format!("cannot verify the fence: image `{image}` has none of python3, nc or bash")));
    }
    Ok(())
}
