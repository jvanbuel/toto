//! The smallest IMAP client that reads new mail from one folder: `LOGIN`, `SELECT`,
//! `UID SEARCH`, `UID FETCH … BODY.PEEK[]`, `LOGOUT`, over TLS (rustls, the web PKI roots). Mail is
//! never marked read, moved or deleted; the cursor is the highest UID handled.

use super::email::{Fetched, MailSource};
use crate::{Error, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

pub struct Imap {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub folder: String,
    /// Plain TCP, for a local test server only; never for a real mailbox.
    pub plaintext: bool,
}

/// Largest message read (bigger ones are skipped, never parsed).
const MAX_MESSAGE: usize = 10 << 20;

fn ierr(e: impl std::fmt::Display) -> Error {
    Error::Queue(format!("IMAP: {e}"))
}

/// An IMAP quoted string.
fn quoted(s: &str) -> Result<String> {
    if s.chars().any(|c| c == '\r' || c == '\n' || !c.is_ascii()) {
        return Err(ierr("user names, passwords and folders must be ASCII without line breaks"));
    }
    Ok(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// `{123}` (or `{123+}`) at the end of a line: a literal of that many bytes follows.
fn literal_len(line: &str) -> Option<usize> {
    let open = line.strip_suffix('}')?.rfind('{')?;
    line[open + 1..line.len() - 1].trim_end_matches('+').parse().ok()
}

struct Session {
    r: BufReader<Box<dyn Stream>>,
    n: u32,
}

/// One response: its text (literals replaced by their length marker) and the literals in order.
type Response = (String, Vec<Vec<u8>>);

impl Session {
    fn read_response(&mut self) -> Result<Response> {
        let (mut text, mut lits) = (String::new(), vec![]);
        loop {
            let mut buf = vec![];
            if self.r.by_ref().take(64 * 1024).read_until(b'\n', &mut buf)? == 0 {
                return Err(ierr("the server closed the connection"));
            }
            let line = String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string();
            text.push_str(&line);
            match literal_len(&line) {
                Some(n) if n <= MAX_MESSAGE => {
                    let mut data = vec![0u8; n];
                    self.r.read_exact(&mut data)?;
                    lits.push(data);
                }
                Some(n) => return Err(ierr(format!("a {n}-byte literal is larger than the limit"))),
                None => return Ok((text, lits)),
            }
        }
    }

    fn command(&mut self, cmd: &str) -> Result<Vec<Response>> {
        self.n += 1;
        let tag = format!("t{}", self.n);
        let w = self.r.get_mut();
        w.write_all(format!("{tag} {cmd}\r\n").as_bytes())?;
        w.flush()?;
        let mut out = vec![];
        loop {
            let resp = self.read_response()?;
            if let Some(rest) = resp.0.strip_prefix(&format!("{tag} ")) {
                if rest.starts_with("OK") {
                    return Ok(out);
                }
                let verb = cmd.split_whitespace().next().unwrap_or("");
                return Err(ierr(format!("{verb}: {rest}")));
            }
            out.push(resp);
        }
    }
}

impl Imap {
    fn connect(&self) -> Result<Session> {
        let addr = (self.host.as_str(), self.port).to_socket_addrs()?.next().ok_or_else(|| ierr(format!("cannot resolve {}", self.host)))?;
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(20))?;
        tcp.set_read_timeout(Some(Duration::from_secs(60)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(60)))?;
        let stream: Box<dyn Stream> = if self.plaintext {
            Box::new(tcp)
        } else {
            let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(ierr)?
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(self.host.clone()).map_err(ierr)?;
            let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(ierr)?;
            Box::new(rustls::StreamOwned::new(conn, tcp))
        };
        let mut s = Session { r: BufReader::new(stream), n: 0 };
        let greeting = s.read_response()?;
        if !greeting.0.starts_with("* OK") {
            return Err(ierr(format!("unexpected greeting: {}", greeting.0)));
        }
        s.command(&format!("LOGIN {} {}", quoted(&self.user)?, quoted(&self.password)?))?;
        Ok(s)
    }
}

impl MailSource for Imap {
    fn fetch(&self, validity: Option<u32>, after: u32, max: usize) -> Result<Fetched> {
        let mut s = self.connect()?;
        let selected = s.command(&format!("SELECT {}", quoted(&self.folder)?))?;
        let now_validity = selected.iter().find_map(|(t, _)| t.split("UIDVALIDITY ").nth(1)?.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()).ok_or_else(|| ierr("SELECT gave no UIDVALIDITY"))?;
        // A new UIDVALIDITY renumbers the folder: start over (core recognises what it has seen).
        let after = if validity == Some(now_validity) { after } else { 0 };
        let found = s.command(&format!("UID SEARCH UID {}:*", after + 1))?;
        let mut uids: Vec<u32> = found.iter().filter_map(|(t, _)| t.strip_prefix("* SEARCH")).flat_map(|t| t.split_whitespace().filter_map(|u| u.parse().ok()).collect::<Vec<u32>>()).filter(|u| *u > after).collect();
        uids.sort_unstable();
        uids.dedup();
        uids.truncate(max);
        let (mut messages, mut too_large) = (vec![], vec![]);
        for uid in uids {
            // Ask for the size first, so one oversized message never blocks the folder.
            let size = s.command(&format!("UID FETCH {uid} (RFC822.SIZE)"))?.iter().find_map(|(t, _)| t.split("RFC822.SIZE ").nth(1)?.split(|c: char| !c.is_ascii_digit()).next()?.parse::<usize>().ok());
            if size.is_none_or(|n| n > MAX_MESSAGE) {
                too_large.push(uid);
                continue;
            }
            let resps = s.command(&format!("UID FETCH {uid} (BODY.PEEK[])"))?;
            if let Some(raw) = resps.into_iter().find_map(|(t, mut l)| (t.contains("FETCH") && !l.is_empty()).then(|| l.remove(0))) {
                messages.push((uid, raw));
            }
        }
        let _ = s.command("LOGOUT");
        Ok(Fetched { validity: now_validity, messages, too_large })
    }
}
