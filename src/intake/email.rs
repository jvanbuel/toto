//! Email as an [`Inbound`]: a mail to the project's inbox is a request; a reply to a mail of a task
//! is a refinement; a reply that says `done` (or `cancel`) on its first line ends the task.
//!
//! What the connector vouches for, and nothing more:
//! - **DKIM**, as the inbox's own provider recorded it in `Authentication-Results` (only the topmost
//!   header carrying the configured `authserv_id` counts: earlier hops' headers can be forged by the
//!   sender), with a passing signature whose domain is aligned with the From address;
//! - the **secret plus-address** the mail was sent to (`inbox+<tag>@domain`): reported as the
//!   SHA-256 of the tag, never the tag, and only for tags of 32 characters or more;
//! - that the inbox is named in `To` or `Cc`, so a forwarded mail that still passes DKIM does not
//!   count.
//!
//! Automated mail (`Auto-Submitted`, `Precedence: bulk|list|junk`, `List-Id`, mail from the inbox
//! itself) is skipped and never answered, so two robots cannot loop.

use super::{Author, Cursor, Inbound, ItemRef, Received, SignalKind, ThreadRef, Verification};
use crate::Result;
use mail_parser::{HeaderValue, MessageParser};
use serde::{Deserialize, Serialize};

fn d_port() -> u16 {
    993
}
fn d_password_env() -> String {
    "TOTO_IMAP_PASSWORD".into()
}
fn d_folder() -> String {
    "INBOX".into()
}
fn d_max() -> usize {
    50
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The address people write to.
    pub address: String,
    pub imap_host: String,
    #[serde(default = "d_port")]
    pub imap_port: u16,
    /// IMAP login; default: `address`.
    #[serde(default)]
    pub user: Option<String>,
    /// Environment variable holding the (app) password.
    #[serde(default = "d_password_env")]
    pub password_env: String,
    #[serde(default = "d_folder")]
    pub folder: String,
    /// The inbox provider's id in `Authentication-Results` (Gmail: `mx.google.com`; otherwise the
    /// first word of the topmost `Authentication-Results` header of a mail the inbox received).
    /// Only results it recorded are believed.
    pub authserv_id: String,
    /// Most mails read per pass.
    #[serde(default = "d_max")]
    pub max_per_pass: usize,
}

impl Config {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !self.address.contains('@') || self.address != self.address.to_lowercase() {
            return Err(format!("intake config: email.address `{}` must be a lower-case mail address", self.address));
        }
        if self.authserv_id.trim().is_empty() {
            return Err("intake config: email.authserv_id is required (whose Authentication-Results to believe)".into());
        }
        Ok(())
    }
}

/// New mail from a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub validity: u32,
    pub messages: Vec<(u32, Vec<u8>)>,
    /// UIDs of messages too large to read; skipped.
    pub too_large: Vec<u32>,
}

/// Where mail comes from: IMAP ([`super::imap::Imap`]) or, in tests, a fake.
pub trait MailSource {
    /// Messages with a UID above `after` (all of them if `validity` is not the folder's current
    /// UIDVALIDITY), at most `max`, oldest first.
    fn fetch(&self, validity: Option<u32>, after: u32, max: usize) -> Result<Fetched>;
}

pub struct EmailInbound<'a> {
    pub cfg: Config,
    pub source: &'a dyn MailSource,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MailCursor {
    validity: Option<u32>,
    #[serde(default)]
    uid: u32,
}

/// A parsed mail, with what the connector can vouch for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    pub id: ItemRef,
    pub from: String,
    pub subject: String,
    pub body: String,
    pub thread: Vec<ItemRef>,
    pub dkim: bool,
    pub tag_sha256: Option<String>,
    pub addressed: bool,
    /// Why this is automated mail, if it is.
    pub automated: Option<String>,
}

fn lower_addr(a: &mail_parser::Addr) -> Option<String> {
    a.address().map(|s| s.trim().to_lowercase())
}

fn id_list(v: &HeaderValue) -> Vec<String> {
    match v {
        HeaderValue::Text(t) => vec![t.to_string()],
        HeaderValue::TextList(l) => l.iter().map(|t| t.to_string()).collect(),
        _ => vec![],
    }
}

fn domain_of(addr: &str) -> &str {
    addr.rsplit_once('@').map_or("", |x| x.1)
}

/// Raw values of every header with this name, top to bottom (unfolded).
fn raw_headers(msg: &mail_parser::Message, name: &str) -> Vec<String> {
    let raw = msg.raw_message();
    msg.headers()
        .iter()
        .filter(|h| h.name().eq_ignore_ascii_case(name))
        .filter_map(|h| raw.get(h.offset_start() as usize..h.offset_end() as usize))
        .map(|b| String::from_utf8_lossy(b).replace("\r\n", " ").replace('\n', " ").trim().to_string())
        .collect()
}

/// Removes `(comments)` from a header value (RFC 8601 allows them anywhere).
fn strip_comments(s: &str) -> String {
    let (mut out, mut depth) = (String::new(), 0u32);
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Whether the topmost `Authentication-Results` from `authserv_id` records a DKIM pass for a domain
/// aligned with `from_domain` (relaxed: the same domain, or one a subdomain of the other).
pub fn dkim_aligned(results: &[String], authserv_id: &str, from_domain: &str) -> bool {
    let Some(ours) = results.iter().map(|r| strip_comments(r)).find(|r| r.split(';').next().and_then(|id| id.split_whitespace().next()).is_some_and(|id| id.eq_ignore_ascii_case(authserv_id))) else {
        return false;
    };
    let from = from_domain.to_lowercase();
    ours.split(';').skip(1).any(|res| {
        let mut words = res.split_whitespace();
        if !words.next().is_some_and(|w| w.eq_ignore_ascii_case("dkim=pass")) {
            return false;
        }
        words.filter_map(|w| w.split_once('=')).any(|(k, v)| {
            let d = match k.to_lowercase().as_str() {
                "header.d" => v.to_lowercase(),
                "header.i" => domain_of(v).to_lowercase(),
                _ => return false,
            };
            let d = d.trim_matches('"');
            !d.is_empty() && (from == d || from.ends_with(&format!(".{d}")) || d.ends_with(&format!(".{from}")))
        })
    })
}

/// The reply without what it quotes: `>` lines, and everything from an "On … wrote:" line, an
/// "Original Message" separator or a signature separator on.
pub fn strip_quoted(body: &str) -> String {
    let mut out: Vec<&str> = vec![];
    for line in body.lines() {
        let t = line.trim_end();
        if t.starts_with('>') {
            continue;
        }
        if t.ends_with("wrote:") && t.len() < 300 {
            if !t.starts_with("On ") && out.last().is_some_and(|l| l.starts_with("On ")) {
                out.pop(); // the attribution line wrapped
            }
            break;
        }
        if t == "--" || t == "-- " || t.starts_with("-----Original Message-----") || t.starts_with("________________________________") {
            break;
        }
        out.push(t);
    }
    while out.last().is_some_and(|l| l.trim().is_empty()) {
        out.pop();
    }
    while out.first().is_some_and(|l| l.trim().is_empty()) {
        out.remove(0);
    }
    out.join("\n")
}

/// Parses a raw mail into what the connector reports. `None` if it is not a mail at all.
pub fn parse(raw: &[u8], cfg: &Config, fallback_id: &str) -> Option<Mail> {
    let msg = MessageParser::default().parse(raw)?;
    let from = msg.from().and_then(|a| a.first()).and_then(lower_addr).unwrap_or_default();
    let (inbox_local, inbox_domain) = cfg.address.rsplit_once('@').unwrap_or((&cfg.address, ""));
    let mut addressed = false;
    let mut tag = None;
    for a in msg.to().into_iter().chain(msg.cc()).flat_map(|l| l.iter()).filter_map(lower_addr) {
        let Some((local, domain)) = a.rsplit_once('@') else { continue };
        if domain != inbox_domain {
            continue;
        }
        if local == inbox_local {
            addressed = true;
        } else if let Some(t) = local.strip_prefix(&format!("{inbox_local}+")) {
            addressed = true;
            // The tag as written (local parts are case-sensitive), found again in the raw To/Cc.
            let raw_tag = raw_headers(&msg, "to").into_iter().chain(raw_headers(&msg, "cc")).find_map(|h| {
                let start = h.to_lowercase().find(&format!("{inbox_local}+{t}@"))? + inbox_local.len() + 1;
                h.get(start..start + t.len()).map(String::from)
            });
            if t.len() >= 32 {
                tag = raw_tag.map(|t| crate::archive::sha256_hex(t.as_bytes()));
            }
        }
    }
    let auto_submitted = raw_headers(&msg, "auto-submitted").into_iter().next().map(|v| v.to_lowercase());
    let precedence = raw_headers(&msg, "precedence").into_iter().next().map(|v| v.to_lowercase());
    let automated = if auto_submitted.as_deref().is_some_and(|v| !v.starts_with("no")) {
        Some(format!("automated mail (Auto-Submitted: {})", auto_submitted.unwrap_or_default()))
    } else if precedence.as_deref().is_some_and(|v| ["bulk", "list", "junk"].iter().any(|p| v.starts_with(p))) {
        Some(format!("bulk or list mail (Precedence: {})", precedence.unwrap_or_default()))
    } else if !raw_headers(&msg, "list-id").is_empty() {
        Some("mailing-list mail (List-Id)".into())
    } else if from == cfg.address || from.starts_with(&format!("{inbox_local}+")) && domain_of(&from) == inbox_domain {
        Some("mail from the inbox itself".into())
    } else {
        None
    };
    let mut thread: Vec<ItemRef> = vec![];
    for i in id_list(msg.in_reply_to()).into_iter().chain(id_list(msg.references())) {
        let r = ItemRef::new(format!("mail:{}", i.trim_matches(['<', '>'])));
        if !thread.contains(&r) {
            thread.push(r);
        }
    }
    let id = msg.message_id().map_or_else(|| ItemRef::new(format!("mail:{fallback_id}")), |m| ItemRef::new(format!("mail:{m}")));
    Some(Mail {
        id,
        dkim: dkim_aligned(&raw_headers(&msg, "authentication-results"), &cfg.authserv_id, domain_of(&from)),
        from,
        subject: msg.subject().unwrap_or("").trim().to_string(),
        body: strip_quoted(&msg.body_text(0).unwrap_or_default()),
        thread,
        tag_sha256: tag,
        addressed,
        automated,
    })
}

impl Mail {
    /// What core is told about this mail.
    pub fn received(self) -> Received {
        if let Some(why) = self.automated {
            return Received::Skipped { id: self.id, from: self.from, reason: why };
        }
        if !self.addressed {
            return Received::Skipped { id: self.id, from: self.from, reason: "the inbox is not in To or Cc (a forward?)".into() };
        }
        if self.from.is_empty() {
            return Received::Skipped { id: self.id, from: String::new(), reason: "no From address".into() };
        }
        let author = Author { address: self.from, verified: if self.dkim { Verification::Dkim } else { Verification::None }, maintainer: false, tag_sha256: self.tag_sha256 };
        if !self.thread.is_empty() {
            let first = self.body.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").trim_end_matches(['.', '!']).to_lowercase();
            let kind = match first.as_str() {
                "done" | "/done" => Some(SignalKind::Done),
                "cancel" | "/cancel" => Some(SignalKind::Cancel),
                "reopen" | "/reopen" => Some(SignalKind::Reopen),
                _ => None,
            };
            if let Some(kind) = kind {
                return Received::Signal { id: self.id, thread: ThreadRef(self.thread), author, kind };
            }
        }
        let thread = (!self.thread.is_empty()).then_some(ThreadRef(self.thread));
        Received::Message { id: self.id, thread, author, subject: Some(self.subject), body: self.body }
    }
}

impl Inbound for EmailInbound<'_> {
    fn name(&self) -> &str {
        "email"
    }

    fn receive(&self, since: &Cursor) -> Result<(Vec<Received>, Cursor)> {
        let cur: MailCursor = serde_json::from_value(since.0.clone()).unwrap_or_default();
        let f = self.source.fetch(cur.validity, cur.uid, self.cfg.max_per_pass)?;
        let restart = cur.validity != Some(f.validity);
        let mut last = if restart { 0 } else { cur.uid };
        let mut out = vec![];
        for (uid, raw) in &f.messages {
            last = last.max(*uid);
            match parse(raw, &self.cfg, &format!("uid-{}-{uid}", f.validity)) {
                Some(m) => out.push(m.received()),
                None => out.push(Received::Skipped { id: ItemRef::new(format!("mail:uid-{}-{uid}", f.validity)), from: String::new(), reason: "not a parsable mail".into() }),
            }
        }
        for uid in &f.too_large {
            last = last.max(*uid);
            out.push(Received::Skipped { id: ItemRef::new(format!("mail:uid-{}-{uid}", f.validity)), from: String::new(), reason: "too large to read".into() });
        }
        Ok((out, Cursor(serde_json::to_value(MailCursor { validity: Some(f.validity), uid: last })?)))
    }
}
