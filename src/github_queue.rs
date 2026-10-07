//! GitHub issues as the queue (ADR 1's simple v1 option); the format is in `docs/github-queue.md`.
//!
//! A task is an open issue labelled `toto` whose body holds the signed envelope. Everything a runner
//! does is a *comment*, which any GitHub user may add to a public repository's issues: a claim
//! comment is the lease (a heartbeat edits it), result comments carry the signed result in parts,
//! and bundles are release assets that only the project uploads.
//!
//! Who holds a lease is decided from GitHub's own comment order and timestamps, never from a runner
//! clock. As with every queue, GitHub is not a trust anchor: the runner checks the project signature
//! on tasks and the project checks the runner's signature on results.

use crate::dsse::Envelope;
use crate::manifest::peek_manifest;
use crate::queue::QueueClient;
use crate::result::SignedResult;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

pub const DEFAULT_API: &str = "https://api.github.com";
pub const DEFAULT_LABEL: &str = "toto";
const BUNDLE_RELEASE: &str = "toto-bundles";
/// GitHub caps comments at 65,536 characters; stay under it, in bytes.
const PART_BYTES: usize = 60_000;
const MAX_PARTS: usize = 8;
const MAX_ISSUE_BODY: usize = 64 * 1024;
const MAX_LEASE: Duration = Duration::from_secs(6 * 3600);
const MAX_BUNDLE: u64 = 256 << 20;

fn qerr(e: impl std::fmt::Display) -> Error {
    Error::Queue(e.to_string())
}

// ------------------------------------------------------------------------------ pure format code

/// The author of an issue or comment.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct User {
    pub login: String,
    /// `User` or `Bot`.
    #[serde(default, rename = "type")]
    pub kind: String,
}

impl User {
    pub fn is_bot(&self) -> bool {
        self.kind == "Bot" || self.login.ends_with("[bot]")
    }
}

/// An issue or pull request as the issues API lists it.
#[derive(Debug, Deserialize, Clone)]
pub struct IssueInfo {
    pub number: u64,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub comments: u64,
    #[serde(default)]
    pub user: Option<User>,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub pull_request: Option<serde_json::Value>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

impl IssueInfo {
    pub fn is_pull(&self) -> bool {
        self.pull_request.is_some()
    }
    pub fn closed(&self) -> bool {
        self.state == "closed"
    }
    /// For a pull request: whether it was merged (the issues API carries `merged_at`).
    pub fn merged(&self) -> bool {
        self.pull_request.as_ref().is_some_and(|p| p.get("merged_at").is_some_and(|m| !m.is_null()))
    }
}

type Issue = IssueInfo;

#[derive(Debug, Deserialize, Clone)]
pub struct Comment {
    pub id: u64,
    #[serde(default)]
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub user: Option<User>,
}

/// What the project side recorded on an attempt's task issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptReport {
    pub issue: u64,
    pub closed: bool,
    /// The first verified result, if any.
    pub result: Option<crate::result::TaskResult>,
    /// `pr` (handled: a pull request, a text answer or no change) or `skip` (refused), with the
    /// marker's values (`pr=<n>`) and the comment text.
    pub handled: Option<(String, HashMap<String, String>, String)>,
}

/// The envelope in an issue body: the first fenced code block after the `toto:task` marker.
pub fn task_body(env: &Envelope, title_note: &str) -> Result<String> {
    Ok(format!("<!-- toto:task -->\n{title_note}\n\n```json\n{}\n```\n", serde_json::to_string_pretty(env)?))
}

fn parse_task(body: &str) -> Option<Envelope> {
    if body.len() > MAX_ISSUE_BODY {
        return None;
    }
    let rest = body.split("<!-- toto:task -->").nth(1)?;
    let json = rest.split("```json").nth(1)?.split("```").next()?;
    serde_json::from_str(json).ok()
}

/// `<!-- toto:<kind> key=value ... -->` on the first line of a comment.
fn marker(body: &str) -> Option<(&str, HashMap<&str, &str>)> {
    let line = body.lines().next()?.trim().strip_prefix("<!-- toto:")?.strip_suffix("-->")?;
    let mut it = line.split_whitespace();
    let kind = it.next()?;
    Some((kind, it.filter_map(|kv| kv.split_once('=')).collect()))
}

fn claim_body(runner: &str, lease: Duration, released: bool, beat: i64) -> String {
    format!(
        "<!-- toto:claim runner={runner} lease={} released={} beat={beat} -->\nRunner `{}` {} this task.",
        lease.as_secs(),
        u8::from(released),
        &runner[..runner.len().min(8)],
        if released { "released" } else { "is working on" },
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub runner: String,
    pub comment: u64,
    end: DateTime<Utc>,
}

/// Replays the claim comments in order. A claim wins if nobody holds the lease at the moment it was
/// created, or its author already holds it; a holder's lease ends `lease` after the comment's last
/// edit (a heartbeat is an edit; a release ends it at once).
pub fn holder_at(comments: &[(u64, String, DateTime<Utc>, DateTime<Utc>)], now: DateTime<Utc>) -> Option<Holder> {
    let mut holder: Option<Holder> = None;
    for (id, body, created, updated) in comments {
        let Some(("claim", kv)) = marker(body) else { continue };
        let (Some(runner), Some(lease)) = (kv.get("runner"), kv.get("lease").and_then(|l| l.parse::<i64>().ok())) else { continue };
        let lease = lease.clamp(1, MAX_LEASE.as_secs() as i64);
        let end = *updated + if kv.get("released") == Some(&"1") { chrono::Duration::zero() } else { chrono::Duration::seconds(lease) };
        let free = holder.as_ref().is_none_or(|h| h.end <= *created || h.runner == *runner);
        if free {
            holder = Some(Holder { runner: runner.to_string(), comment: *id, end });
        }
    }
    holder.filter(|h| h.end > now)
}

/// Splits a result's JSON into comment bodies, each tagged so they can be reassembled.
fn result_parts(runner: &str, json: &str) -> Result<Vec<String>> {
    let sum = &crate::archive::sha256_hex(json.as_bytes())[..12];
    let mut chunks = vec![];
    let mut rest = json;
    while !rest.is_empty() {
        let mut cut = rest.len().min(PART_BYTES);
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        chunks.push(&rest[..cut]);
        rest = &rest[cut..];
    }
    if chunks.len() > MAX_PARTS {
        return Err(qerr(format!("result is {} bytes; a GitHub queue carries at most {} (lower the task's max_artifact_bytes)", json.len(), MAX_PARTS * PART_BYTES)));
    }
    let n = chunks.len();
    Ok(chunks.iter().enumerate().map(|(i, c)| format!("<!-- toto:result runner={runner} sum={sum} part={}/{n} -->\n```json\n{c}\n```", i + 1)).collect())
}

/// One result comment: part number, part count, text.
type Part = (usize, usize, String);

/// Complete, signature-checked results for `task_id` found in a comment list.
fn results_in(comments: &[Comment], task_id: &str) -> Vec<SignedResult> {
    let mut groups: HashMap<(String, String), Vec<Part>> = HashMap::new();
    let mut first: HashMap<(String, String), u64> = HashMap::new();
    for c in comments {
        let Some(("result", kv)) = marker(&c.body) else { continue };
        let (Some(runner), Some(sum), Some((i, n))) = (kv.get("runner"), kv.get("sum"), kv.get("part").and_then(|p| p.split_once('/'))) else { continue };
        let (Ok(i), Ok(n)) = (i.parse::<usize>(), n.parse::<usize>()) else { continue };
        let Some(text) = c.body.split("```json\n").nth(1).and_then(|t| t.rsplit_once("\n```")).map(|(t, _)| t.to_string()) else { continue };
        if (1..=MAX_PARTS).contains(&n) && (1..=n).contains(&i) {
            let key = (runner.to_string(), sum.to_string());
            first.entry(key.clone()).and_modify(|f| *f = (*f).min(c.id)).or_insert(c.id);
            groups.entry(key).or_default().push((i, n, text));
        }
    }
    let mut out = vec![];
    let mut ordered: Vec<_> = groups.into_iter().collect();
    ordered.sort_by_key(|(k, _)| first[k]); // the earliest result first, whatever the map order
    for ((_, sum), mut parts) in ordered {
        parts.sort_by_key(|p| p.0);
        parts.dedup_by_key(|p| p.0);
        let n = parts[0].1;
        if parts.len() != n || parts.iter().any(|p| p.1 != n) || parts.iter().enumerate().any(|(k, p)| p.0 != k + 1) {
            continue;
        }
        let json: String = parts.into_iter().map(|p| p.2).collect();
        if crate::archive::sha256_hex(json.as_bytes())[..12] != sum {
            continue;
        }
        if let Ok(r) = serde_json::from_str::<SignedResult>(&json)
            && r.open().is_ok_and(|b| b.task_id == task_id)
        {
            out.push(r);
        }
    }
    out
}

// -------------------------------------------------------------------------------------- the client

/// A task whose result is in, as seen by the project.
pub struct Finished {
    pub issue: u64,
    pub manifest: crate::manifest::TaskManifest,
    pub result: SignedResult,
    pub handled: bool,
}

/// Marker for the comment the project leaves once it has dealt with a result.
pub fn handled_comment(kind: &str, task_id: &str, runner: &str, text: &str) -> String {
    format!("<!-- toto:{kind} task={task_id} runner={runner} -->\n{text}")
}

/// The same, naming the pull request the result went into.
pub fn handled_comment_pr(task_id: &str, runner: &str, pr: u64, text: &str) -> String {
    format!("<!-- toto:pr task={task_id} runner={runner} pr={pr} -->\n{text}")
}

/// Whether a text is one toto wrote (every toto comment and issue body starts with a marker).
pub fn is_toto_text(body: &str) -> bool {
    body.trim_start().starts_with("<!-- toto:")
}

#[derive(Default)]
struct Cache {
    issue_of: HashMap<String, u64>,
    claim_of: HashMap<String, u64>,
    etags: HashMap<String, (String, Vec<u8>)>,
}

pub struct GitHubQueue {
    api: String,
    repo: String,
    label: String,
    token: Option<String>,
    agent: ureq::Agent,
    cache: Mutex<Cache>,
}

impl GitHubQueue {
    /// `repo` is `owner/name`. Without a token only reads work (and at a low rate limit).
    pub fn new(api: &str, repo: &str, label: &str, token: Option<String>) -> Self {
        let agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(60))).build().into();
        Self { api: api.trim_end_matches('/').to_string(), repo: repo.into(), label: label.into(), token, agent, cache: Mutex::default() }
    }

    fn request(&self, method: &str, url: &str, body: Option<Vec<u8>>, ctype: &str, accept: &str, etag: Option<&str>) -> Result<(u16, Vec<u8>, ureq::http::HeaderMap)> {
        let mut req = ureq::http::Request::builder().method(method).uri(url).header("accept", accept).header("x-github-api-version", "2022-11-28").header("user-agent", "toto");
        if let Some(t) = &self.token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        if let Some(e) = etag {
            req = req.header("if-none-match", e);
        }
        let req = req.header("content-type", ctype).body(body.unwrap_or_default()).map_err(qerr)?;
        let mut resp = self.agent.run(req).map_err(|e| qerr(format!("{url}: {e}")))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let bytes = resp.body_mut().with_config().limit(MAX_BUNDLE).read_to_vec().map_err(qerr)?;
        Ok((status, bytes, headers))
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/repos/{}{path}", self.api, self.repo)
    }

    fn fail(status: u16, what: &str, body: &[u8]) -> Error {
        let hint = match status {
            401 | 403 => " (is the token valid, and does it allow issues on this repository? a rate limit also answers 403)",
            404 => " (repository not found, or no access)",
            _ => "",
        };
        qerr(format!("GitHub {what}: HTTP {status}{hint}: {}", String::from_utf8_lossy(body).chars().take(160).collect::<String>()))
    }

    /// GET with ETag revalidation, so unchanged polls cost no rate limit. Returns body and server time.
    fn get(&self, url: &str) -> Result<(Vec<u8>, DateTime<Utc>)> {
        let cached = self.cache.lock().unwrap().etags.get(url).cloned();
        let (status, body, headers) = self.request("GET", url, None, "application/json", "application/vnd.github+json", cached.as_ref().map(|c| c.0.as_str()))?;
        let now = headers.get("date").and_then(|d| d.to_str().ok()).and_then(|d| DateTime::parse_from_rfc2822(d).ok()).map_or_else(Utc::now, |d| d.with_timezone(&Utc));
        match (status, cached) {
            (304, Some((_, body))) => Ok((body, now)),
            (200, _) => {
                if let Some(e) = headers.get("etag").and_then(|e| e.to_str().ok()) {
                    self.cache.lock().unwrap().etags.insert(url.to_string(), (e.to_string(), body.clone()));
                }
                Ok((body, now))
            }
            _ => Err(Self::fail(status, "GET", &body)),
        }
    }

    fn send_json(&self, method: &str, url: &str, v: &serde_json::Value) -> Result<serde_json::Value> {
        let (status, body, _) = self.request(method, url, Some(serde_json::to_vec(v)?), "application/json", "application/vnd.github+json", None)?;
        if !(200..300).contains(&status) {
            return Err(Self::fail(status, method, &body));
        }
        Ok(serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
    }

    fn pages<T: for<'de> Deserialize<'de>>(&self, base: &str) -> Result<(Vec<T>, DateTime<Utc>)> {
        let (mut all, mut now) = (vec![], Utc::now());
        for page in 1..=20 {
            let sep = if base.contains('?') { '&' } else { '?' };
            let (body, t) = self.get(&format!("{base}{sep}per_page=100&page={page}"))?;
            now = t;
            let items: Vec<T> = serde_json::from_slice(&body)?;
            let n = items.len();
            all.extend(items);
            if n < 100 {
                break;
            }
        }
        Ok((all, now))
    }

    fn task_issues(&self, state: &str) -> Result<Vec<(Issue, Envelope, String)>> {
        let (issues, _): (Vec<Issue>, _) = self.pages(&self.api_url(&format!("/issues?labels={}&state={state}", self.label)))?;
        let mut out = vec![];
        for i in issues.into_iter().filter(|i| i.pull_request.is_none()) {
            let Some(env) = i.body.as_deref().and_then(parse_task) else { continue };
            let Ok(m) = peek_manifest(&env) else { continue };
            self.cache.lock().unwrap().issue_of.insert(m.id.clone(), i.number);
            out.push((i, env, m.id));
        }
        Ok(out)
    }

    fn issue_number(&self, task_id: &str) -> Result<u64> {
        if let Some(n) = self.cache.lock().unwrap().issue_of.get(task_id) {
            return Ok(*n);
        }
        self.task_issues("open")?;
        self.cache.lock().unwrap().issue_of.get(task_id).copied().ok_or_else(|| qerr(format!("no open `{}` issue carries task `{task_id}`", self.label)))
    }

    fn comments(&self, issue: u64) -> Result<(Vec<Comment>, DateTime<Utc>)> {
        self.pages(&self.api_url(&format!("/issues/{issue}/comments")))
    }

    fn holder(comments: &[Comment], now: DateTime<Utc>) -> Option<Holder> {
        let tuples: Vec<_> = comments.iter().map(|c| (c.id, c.body.clone(), c.created_at, c.updated_at)).collect();
        holder_at(&tuples, now)
    }

    /// Every verified result found on the project's task issues, open or closed (project side).
    pub fn results(&self) -> Result<Vec<SignedResult>> {
        let mut out = vec![];
        for (issue, _, id) in self.task_issues("all")? {
            if issue.comments > 0 {
                out.extend(results_in(&self.comments(issue.number)?.0, &id));
            }
        }
        Ok(out)
    }

    /// Opens a task issue (project side; the token needs to create issues and labels).
    pub fn post_task(&self, env: &Envelope) -> Result<u64> {
        let m = peek_manifest(env)?;
        let title = format!("[toto] {}: {}", m.id, m.kind);
        let note = format!("Task `{}` for project `{}`. Runners claim it with a comment; do not edit this issue's body.", m.id, m.project_id);
        let v = self.send_json("POST", &self.api_url("/issues"), &serde_json::json!({"title": title, "body": task_body(env, &note)?, "labels": [self.label]}))?;
        v["number"].as_u64().ok_or_else(|| qerr("GitHub did not return an issue number"))
    }

    /// Stores a bundle as the release asset named by its hash (project side; needs contents write).
    pub fn upload_bundle(&self, bytes: &[u8]) -> Result<String> {
        let hash = crate::archive::sha256_hex(bytes);
        let release = match self.release() {
            Some(r) => r,
            None => self.send_json("POST", &self.api_url("/releases"), &serde_json::json!({"tag_name": BUNDLE_RELEASE, "name": "toto bundles", "body": "Input bundles for toto tasks, named by SHA-256.", "prerelease": true}))?,
        };
        if release["assets"].as_array().is_some_and(|a| a.iter().any(|x| x["name"] == hash.as_str())) {
            return Ok(hash);
        }
        let upload = release["upload_url"].as_str().ok_or_else(|| qerr("release has no upload_url"))?.split('{').next().unwrap_or("").to_string();
        let (status, body, _) = self.request("POST", &format!("{upload}?name={hash}"), Some(bytes.to_vec()), "application/octet-stream", "application/vnd.github+json", None)?;
        if !(200..300).contains(&status) {
            return Err(Self::fail(status, "asset upload", &body));
        }
        Ok(hash)
    }

    /// Open task issues that have a complete, correctly signed result and whose task the project
    /// itself signed (project side). `handled` is true once a PR or skip marker is on the issue.
    pub fn open_results(&self, trusted: &crate::manifest::TrustedProjects) -> Result<Vec<Finished>> {
        let mut out = vec![];
        for (issue, env, id) in self.task_issues("open")? {
            let Ok(manifest) = trusted.verify(&env) else { continue };
            if issue.comments == 0 {
                continue;
            }
            let (comments, _) = self.comments(issue.number)?;
            let Some(result) = results_in(&comments, &id).into_iter().next() else { continue };
            let handled = comments.iter().any(|c| matches!(marker(&c.body), Some(("pr" | "skip", _))));
            out.push(Finished { issue: issue.number, manifest, result, handled });
        }
        Ok(out)
    }

    /// A file from the repository (`None` if it does not exist), at `commit` or the default branch.
    pub fn file_at(&self, path: &str, commit: Option<&str>) -> Result<Option<Vec<u8>>> {
        let q = commit.map_or(String::new(), |c| format!("?ref={c}"));
        let (status, body, _) = self.request("GET", &self.api_url(&format!("/contents/{path}{q}")), None, "application/json", "application/vnd.github.raw+json", None)?;
        match status {
            200 => Ok(Some(body)),
            404 => Ok(None),
            _ => Err(Self::fail(status, "GET", &body)),
        }
    }

    /// A file from the repository's default branch (`None` if it does not exist).
    pub fn file(&self, path: &str) -> Result<Option<Vec<u8>>> {
        self.file_at(path, None)
    }

    /// Entries of a directory: `(path, type)` with type `file` or `dir`.
    fn list_dir(&self, dir: &str, commit: Option<&str>) -> Result<Vec<(String, String)>> {
        let q = commit.map_or(String::new(), |c| format!("?ref={c}"));
        let (status, body, _) = self.request("GET", &self.api_url(&format!("/contents/{dir}{q}")), None, "application/json", "application/vnd.github+json", None)?;
        match status {
            200 => {
                let v: serde_json::Value = serde_json::from_slice(&body)?;
                Ok(v.as_array().into_iter().flatten().filter_map(|e| Some((e["path"].as_str()?.to_string(), e["type"].as_str()?.to_string()))).collect())
            }
            404 => Ok(vec![]),
            _ => Err(Self::fail(status, "GET", &body)),
        }
    }

    pub fn comment(&self, issue: u64, body: &str) -> Result<()> {
        self.send_json("POST", &self.api_url(&format!("/issues/{issue}/comments")), &serde_json::json!({"body": body})).map(|_| ())
    }

    pub fn close_issue(&self, issue: u64) -> Result<()> {
        self.send_json("PATCH", &self.api_url(&format!("/issues/{issue}")), &serde_json::json!({"state": "closed", "state_reason": "completed"})).map(|_| ())
    }

    pub fn reopen_issue(&self, issue: u64) -> Result<()> {
        self.send_json("PATCH", &self.api_url(&format!("/issues/{issue}")), &serde_json::json!({"state": "open"})).map(|_| ())
    }

    pub fn close_pull(&self, number: u64) -> Result<()> {
        self.send_json("PATCH", &self.api_url(&format!("/pulls/{number}")), &serde_json::json!({"state": "closed"})).map(|_| ())
    }

    pub fn edit_comment(&self, id: u64, body: &str) -> Result<()> {
        self.send_json("PATCH", &format!("{}/repos/{}/issues/comments/{id}", self.api, self.repo), &serde_json::json!({"body": body})).map(|_| ())
    }

    /// Opens an issue and returns its number.
    pub fn create_issue(&self, title: &str, body: &str, labels: &[&str]) -> Result<u64> {
        let v = self.send_json("POST", &self.api_url("/issues"), &serde_json::json!({"title": title, "body": body, "labels": labels}))?;
        v["number"].as_u64().ok_or_else(|| qerr("GitHub did not return an issue number"))
    }

    /// One issue or pull request.
    pub fn issue(&self, number: u64) -> Result<IssueInfo> {
        Ok(serde_json::from_slice(&self.get(&self.api_url(&format!("/issues/{number}")))?.0)?)
    }

    /// Issues and pull requests with `label` (`state`: open, closed or all), updated at or after
    /// `since` if given.
    pub fn list_issues(&self, label: &str, state: &str, since: Option<DateTime<Utc>>) -> Result<Vec<IssueInfo>> {
        let since = since.map_or(String::new(), |t| format!("&since={}", t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)));
        Ok(self.pages(&self.api_url(&format!("/issues?labels={label}&state={state}&sort=created&direction=asc{since}")))?.0)
    }

    pub fn issue_comments(&self, number: u64) -> Result<Vec<Comment>> {
        Ok(self.comments(number)?.0)
    }

    /// The account's permission on the repository: `admin`, `write`, `read` or `none`.
    pub fn permission(&self, login: &str) -> Result<String> {
        let (status, body, _) = self.request("GET", &self.api_url(&format!("/collaborators/{login}/permission")), None, "application/json", "application/vnd.github+json", None)?;
        match status {
            200 => Ok(serde_json::from_slice::<serde_json::Value>(&body)?["permission"].as_str().unwrap_or("none").to_string()),
            404 => Ok("none".into()),
            _ => Err(Self::fail(status, "GET", &body)),
        }
    }

    /// A GraphQL request (Projects v2 has no REST API). Errors in the response are errors here.
    pub fn graphql(&self, query: &str, variables: serde_json::Value) -> Result<serde_json::Value> {
        let url = match self.api.strip_suffix("/api/v3") {
            Some(host) => format!("{host}/api/graphql"),
            None => format!("{}/graphql", self.api),
        };
        let v = self.send_json("POST", &url, &serde_json::json!({"query": query, "variables": variables}))?;
        if let Some(errors) = v.get("errors").and_then(|e| e.as_array()).filter(|e| !e.is_empty()) {
            let msgs: Vec<&str> = errors.iter().filter_map(|e| e["message"].as_str()).collect();
            return Err(qerr(format!("GitHub GraphQL: {}", msgs.join("; "))));
        }
        Ok(v["data"].clone())
    }

    /// Issues carrying a task the project signed, by manifest id (any state): `(issue number,
    /// closed)`. Forged issues are left out, so nobody can pre-post an attempt id to block it.
    pub fn task_index(&self, trusted: &crate::manifest::TrustedProjects) -> Result<HashMap<String, (u64, bool)>> {
        let mut out = HashMap::new();
        for (i, env, id) in self.task_issues("all")? {
            if trusted.verify(&env).is_ok() {
                out.entry(id).or_insert((i.number, i.closed()));
            }
        }
        Ok(out)
    }

    /// What the project side recorded on the task issue of `id`: its first verified result (of a
    /// task the project itself signed) and the handled marker.
    pub fn attempt_report(&self, trusted: &crate::manifest::TrustedProjects, issue: u64, id: &str) -> Result<AttemptReport> {
        let info = self.issue(issue)?;
        let env = info.body.as_deref().and_then(parse_task).ok_or_else(|| qerr(format!("issue #{issue} carries no task")))?;
        let manifest = trusted.verify(&env)?;
        if manifest.id != id {
            return Err(qerr(format!("issue #{issue} carries `{}`, not `{id}`", manifest.id)));
        }
        let comments = if info.comments > 0 { self.comments(issue)?.0 } else { vec![] };
        let result = results_in(&comments, id).into_iter().next().map(|r| r.open()).transpose()?;
        let handled = comments.iter().find_map(|c| match marker(&c.body) {
            Some((k @ ("pr" | "skip"), kv)) if kv.get("task") == Some(&id) => {
                let text = c.body.split_once('\n').map_or("", |x| x.1).to_string();
                Some((k.to_string(), kv.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(), text))
            }
            _ => None,
        });
        Ok(AttemptReport { issue, closed: info.closed(), result, handled })
    }

    /// The open pull request whose head is `branch`, if any.
    pub fn open_pull_for(&self, branch: &str) -> Result<Option<u64>> {
        let owner = self.repo.split('/').next().unwrap_or_default();
        let (body, _) = self.get(&self.api_url(&format!("/pulls?state=open&head={owner}:{branch}")))?;
        Ok(serde_json::from_slice::<Vec<serde_json::Value>>(&body)?.first().and_then(|p| p["number"].as_u64()))
    }

    /// Whether a pull request (open or closed) already exists for the head branch.
    pub fn pull_exists(&self, branch: &str) -> Result<bool> {
        let owner = self.repo.split('/').next().unwrap_or_default();
        let (body, _) = self.get(&self.api_url(&format!("/pulls?state=all&head={owner}:{branch}")))?;
        Ok(!serde_json::from_slice::<Vec<serde_json::Value>>(&body)?.is_empty())
    }

    /// Open pull requests whose head branch starts with `prefix`.
    pub fn open_pulls_with_prefix(&self, prefix: &str) -> Result<usize> {
        let (pulls, _): (Vec<serde_json::Value>, _) = self.pages(&self.api_url("/pulls?state=open"))?;
        Ok(pulls.iter().filter(|p| p["head"]["ref"].as_str().is_some_and(|r| r.starts_with(prefix))).count())
    }

    pub fn open_pull(&self, head: &str, base: &str, title: &str, body: &str) -> Result<u64> {
        let v = self.send_json("POST", &self.api_url("/pulls"), &serde_json::json!({"title": title, "head": head, "base": base, "body": body}))?;
        let n = v["number"].as_u64().ok_or_else(|| qerr("GitHub did not return a pull request number"))?;
        // Best effort: a label makes toto PRs easy to find and filter.
        let _ = self.send_json("POST", &self.api_url(&format!("/issues/{n}/labels")), &serde_json::json!({"labels": [self.label]}));
        Ok(n)
    }

    fn release(&self) -> Option<serde_json::Value> {
        let (body, _) = self.get(&self.api_url(&format!("/releases/tags/{BUNDLE_RELEASE}"))).ok()?;
        serde_json::from_slice(&body).ok()
    }
}

impl QueueClient for GitHubQueue {
    fn available(&self) -> Result<Vec<Envelope>> {
        let mut out = vec![];
        for (issue, env, id) in self.task_issues("open")? {
            if issue.comments > 0 {
                let (comments, now) = self.comments(issue.number)?;
                if Self::holder(&comments, now).is_some() || !results_in(&comments, &id).is_empty() {
                    continue;
                }
            }
            out.push(env);
        }
        Ok(out)
    }

    fn claim(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        let n = self.issue_number(task_id)?;
        let lease = lease.min(MAX_LEASE);
        let (comments, now) = self.comments(n)?;
        if !results_in(&comments, task_id).is_empty() {
            return Err(qerr("task already has a result"));
        }
        match Self::holder(&comments, now) {
            Some(h) if h.runner != runner_id => return Err(qerr("already leased")),
            Some(h) => {
                // Our own earlier claim: extend it instead of adding a comment.
                self.send_json("PATCH", &format!("{}/repos/{}/issues/comments/{}", self.api, self.repo, h.comment), &serde_json::json!({"body": claim_body(runner_id, lease, false, now.timestamp())}))?;
                self.cache.lock().unwrap().claim_of.insert(task_id.into(), h.comment);
                return Ok(());
            }
            None => {}
        }
        let posted = self.send_json("POST", &self.api_url(&format!("/issues/{n}/comments")), &serde_json::json!({"body": claim_body(runner_id, lease, false, now.timestamp())}))?;
        let mine = posted["id"].as_u64().ok_or_else(|| qerr("GitHub did not return a comment id"))?;
        // Re-read: comment order decides, so a runner that posted just before us wins.
        let (after, now) = self.comments(n)?;
        match Self::holder(&after, now) {
            Some(h) if h.comment == mine => {
                self.cache.lock().unwrap().claim_of.insert(task_id.into(), mine);
                Ok(())
            }
            _ => Err(qerr("already leased")),
        }
    }

    fn heartbeat(&self, task_id: &str, runner_id: &str, lease: Duration) -> Result<()> {
        let n = self.issue_number(task_id)?;
        let (comments, now) = self.comments(n)?;
        match Self::holder(&comments, now) {
            Some(h) if h.runner == runner_id => {
                self.send_json("PATCH", &format!("{}/repos/{}/issues/comments/{}", self.api, self.repo, h.comment), &serde_json::json!({"body": claim_body(runner_id, lease.min(MAX_LEASE), false, now.timestamp())}))?;
                Ok(())
            }
            _ => Err(qerr("lease lost")),
        }
    }

    fn release(&self, task_id: &str, runner_id: &str) -> Result<()> {
        let n = self.issue_number(task_id)?;
        let (comments, now) = self.comments(n)?;
        if let Some(h) = Self::holder(&comments, now).filter(|h| h.runner == runner_id) {
            self.send_json("PATCH", &format!("{}/repos/{}/issues/comments/{}", self.api, self.repo, h.comment), &serde_json::json!({"body": claim_body(runner_id, Duration::from_secs(1), true, now.timestamp())}))?;
        }
        self.cache.lock().unwrap().claim_of.remove(task_id);
        Ok(())
    }

    fn submit(&self, result: &SignedResult) -> Result<()> {
        let body = result.open()?;
        let n = self.issue_number(&body.task_id)?;
        let json = serde_json::to_string(result)?;
        let parts = result_parts(&body.runner_id, &json)?;
        // Resume after a partial post: skip the parts already there for this exact result.
        let (existing, _) = self.comments(n)?;
        let have: Vec<String> = existing.iter().filter_map(|c| c.body.lines().next().map(str::to_string)).collect();
        for p in parts {
            if !have.contains(&p.lines().next().unwrap_or_default().to_string()) {
                self.send_json("POST", &self.api_url(&format!("/issues/{n}/comments")), &serde_json::json!({"body": p}))?;
            }
        }
        Ok(())
    }

    fn bundle(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(qerr(format!("invalid bundle hash `{hash}`")));
        }
        let Some(release) = self.release() else { return Ok(None) };
        let Some(url) = release["assets"].as_array().and_then(|a| a.iter().find(|x| x["name"] == hash)).and_then(|x| x["url"].as_str()) else { return Ok(None) };
        let (status, body, _) = self.request("GET", url, None, "application/json", "application/octet-stream", None)?;
        match status {
            200 => Ok(Some(body)),
            404 => Ok(None),
            _ => Err(Self::fail(status, "asset download", &body)),
        }
    }
}

impl crate::projects::RepoFiles for GitHubQueue {
    fn head_commit(&self) -> Result<Option<String>> {
        let (status, body, _) = self.request("GET", &self.api_url("/commits/HEAD"), None, "application/json", "application/vnd.github+json", None)?;
        match status {
            200 => Ok(serde_json::from_slice::<serde_json::Value>(&body)?["sha"].as_str().map(String::from)),
            404 | 409 => Ok(None), // empty repository
            _ => Err(Self::fail(status, "GET", &body)),
        }
    }

    fn file(&self, path: &str, commit: Option<&str>) -> Result<Option<Vec<u8>>> {
        self.file_at(path, commit)
    }

    fn tree(&self, dir: &str, commit: Option<&str>) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
        let mut out = std::collections::BTreeMap::new();
        let mut dirs = vec![dir.trim_end_matches('/').to_string()];
        let root = dirs[0].clone();
        while let Some(d) = dirs.pop() {
            for (path, kind) in self.list_dir(&d, commit)? {
                match kind.as_str() {
                    "dir" => dirs.push(path),
                    "file" => {
                        if out.len() >= crate::agent::MAX_FILES {
                            return Err(qerr(format!("{root} has more than {} files", crate::agent::MAX_FILES)));
                        }
                        let rel = path.strip_prefix(&format!("{root}/")).unwrap_or(&path).to_string();
                        if let Some(bytes) = self.file_at(&path, commit)? {
                            out.insert(rel, bytes);
                        }
                    }
                    _ => {} // symlinks and submodules are not carried
                }
            }
        }
        Ok(out)
    }
}
