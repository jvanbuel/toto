//! `toto-relay`: the one host binary a task container sees, mounted read-only at `/toto/relay`.
//!
//! - `relay 127.0.0.1:<port> <unix socket>`: forwards loopback TCP connections inside the
//!   container to the credential proxy's bind-mounted unix socket, so a container with
//!   `--network none` can still reach exactly one thing. Loopback only.
//! - `probe <addr>`: exit 0 if something accepts connections there (readiness check).
//!
//! Built static (musl) so it runs in any image; it has no dependencies.

fn relay(listen: &str, sock: &str) -> Result<(), String> {
    use std::net::TcpListener;
    use std::os::unix::net::UnixStream;
    if !listen.starts_with("127.0.0.1:") {
        return Err("relay only listens on 127.0.0.1".into());
    }
    let l = TcpListener::bind(listen).map_err(|e| format!("{listen}: {e}"))?;
    for conn in l.incoming().flatten() {
        let sock = sock.to_string();
        std::thread::spawn(move || {
            let Ok(unix) = UnixStream::connect(&sock) else { return };
            let (Ok(mut tcp_r), Ok(mut unix_w)) = (conn.try_clone(), unix.try_clone()) else { return };
            let (mut unix_r, mut tcp_w) = (unix, conn);
            let up = std::thread::spawn(move || {
                let _ = std::io::copy(&mut tcp_r, &mut unix_w);
                let _ = unix_w.shutdown(std::net::Shutdown::Write);
            });
            let _ = std::io::copy(&mut unix_r, &mut tcp_w);
            let _ = tcp_w.shutdown(std::net::Shutdown::Write);
            let _ = up.join();
        });
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match (args.get(1).map(String::as_str), args.get(2), args.get(3)) {
        (Some("relay"), Some(listen), Some(sock)) => relay(listen, sock),
        (Some("probe"), Some(addr), _) => std::process::exit(if std::net::TcpStream::connect(addr).is_ok() { 0 } else { 1 }),
        _ => Err("usage: toto-relay relay 127.0.0.1:<port> <unix socket> | probe <addr>".into()),
    };
    if let Err(e) = result {
        eprintln!("toto-relay: {e}");
        std::process::exit(1);
    }
}
