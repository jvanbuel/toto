//! One pass of `toto project sync` (ADR 16): turn verified results into commits on each task's
//! branch and pull request, read what arrived from every inbound, decide, post the attempts that are
//! due as signed manifests, show every changed task on every outbound, and commit the state.
//!
//! Every step is idempotent, so a pass that fails half way (or loses a race with another pass) is
//! simply run again: attempt ids are deterministic and looked up before posting, an attempt already
//! on its branch is not applied twice, received items already applied are skipped, and outbounds
//! are only called when the task's view changed.

use super::policy::{clean_title, Decision, IntakePolicy};
use super::store::{file_key, Store};
use super::task::{AttemptResult, Event, Role, Task, Turn};
use super::{Author, Cursor, Inbound, ItemRef, Outbound, Received, SignalKind};
use crate::github_queue::GitHubQueue;
use crate::manifest::{OutputSchema, TaskManifest, TrustedProjects};
use crate::pr_flow::Outcome;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

fn d_base() -> String {
    "main".into()
}
fn d_state() -> String {
    "toto-state".into()
}
fn d_max_open() -> usize {
    10
}
fn d_input() -> u64 {
    64 << 20
}
fn d_prompt() -> usize {
    48_000
}
fn d_log_days() -> u32 {
    30
}
fn d_true() -> bool {
    true
}
fn d_label() -> String {
    "toto:request".into()
}

/// The GitHub issues connector: requests from an issue form, comments and commands on request
/// issues and on the task's pull request, and a status comment on the request issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubIntake {
    /// Read requests, comments and commands (the inbound).
    #[serde(default = "d_true")]
    pub requests: bool,
    /// Keep a status comment on each request issue, and mirror requests that came another way to
    /// an issue (the outbound).
    #[serde(default = "d_true")]
    pub status: bool,
    /// The label the issue form applies.
    #[serde(default = "d_label")]
    pub label: String,
}

impl Default for GithubIntake {
    fn default() -> Self {
        Self { requests: true, status: true, label: d_label() }
    }
}

/// `.toto/intake.toml` in the project repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntakeConfig {
    /// The project id runners know the project's key by.
    pub project_id: String,
    /// `owner/name`: the repository whose issues are the queue.
    pub repo: String,
    #[serde(default = "d_base")]
    pub base: String,
    #[serde(default = "d_state")]
    pub state_branch: String,
    /// Keep the state in another repository (`owner/name`, or a git URL) instead of this one: a
    /// private one keeps the sync log and task state out of public view and out of the project's
    /// clones. Needs a token that can push to it (`TOTO_STATE_TOKEN`).
    #[serde(default)]
    pub state_repo: Option<String>,
    /// Days of sync log kept on the state branch.
    #[serde(default = "d_log_days")]
    pub log_days: u32,
    /// Stop opening new pull requests while this many toto pull requests are open.
    #[serde(default = "d_max_open")]
    pub max_open: usize,
    /// Extra paths a result may not touch (see `pr_flow::DEFAULT_PROTECTED`).
    #[serde(default)]
    pub protect: Vec<String>,
    #[serde(default = "d_input")]
    pub max_input_bytes: u64,
    #[serde(default = "d_prompt")]
    pub max_prompt_chars: usize,
    #[serde(default)]
    pub github: GithubIntake,
    #[serde(default)]
    pub projects_v2: Option<super::projects_v2::Config>,
    #[serde(default)]
    pub email: Option<super::email::Config>,
    #[serde(flatten)]
    pub policy: IntakePolicy,
}

impl IntakeConfig {
    pub fn parse(text: &str) -> std::result::Result<Self, String> {
        let c: Self = toml::from_str(text).map_err(|e| format!("intake config: {e}"))?;
        c.policy.validate()?;
        if !crate::directory::valid_repo(&c.repo) {
            return Err(format!("intake config: repo `{}` is not `owner/name`", c.repo));
        }
        if c.state_branch == c.base && c.state_repo.is_none() {
            return Err("intake config: state_branch must not be the base branch".into());
        }
        if let Some(r) = &c.state_repo
            && !crate::directory::valid_repo(r)
            && !r.contains("://")
            && !r.starts_with('/')
        {
            return Err(format!("intake config: state_repo `{r}` is neither `owner/name` nor a git URL"));
        }
        if let Some(e) = &c.email {
            e.validate()?;
        }
        Ok(c)
    }

    /// Where the state branch is: `origin`, or `state_repo` (`owner/name` means github.com).
    pub fn state_location(&self, token: Option<String>) -> super::store::Location {
        match &self.state_repo {
            None => super::store::Location::origin(&self.state_branch),
            Some(r) => {
                let remote = if crate::directory::valid_repo(r) && !r.starts_with('/') { format!("https://github.com/{r}.git") } else { r.clone() };
                super::store::Location { remote, branch: self.state_branch.clone(), token }
            }
        }
    }

    pub fn trusted(&self, key: &SigningKey) -> TrustedProjects {
        let mut t = TrustedProjects::default();
        t.insert(&self.project_id, key.verifying_key());
        t
    }
}

/// One line of the sync log (`log/<date>.jsonl` on the state branch): why something happened, or
/// why nothing did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    pub at: DateTime<Utc>,
    pub what: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub pull_requests: Vec<Outcome>,
    pub log: Vec<LogLine>,
    pub posted: Vec<String>,
    pub published: usize,
    /// Failures that did not stop the pass (an inbound that could not be read, an outbound that
    /// could not be written); the next pass retries them.
    pub errors: Vec<String>,
    pub commit: Option<String>,
}

pub struct Pass<'a> {
    pub cfg: &'a IntakeConfig,
    pub queue: &'a GitHubQueue,
    pub key: &'a SigningKey,
    /// A checkout of the project repository with push access to `origin`.
    pub repo_dir: &'a Path,
    pub inbounds: Vec<&'a dyn Inbound>,
    pub outbounds: Vec<&'a dyn Outbound>,
    /// Where the state branch is ([`IntakeConfig::state_location`]).
    pub state: super::store::Location,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Usage {
    day: String,
    count: u32,
}

struct State<'p, 'a> {
    p: &'p Pass<'a>,
    store: Store,
    tasks: BTreeMap<String, Task>,
    report: Report,
}

pub fn run(p: &Pass) -> Result<Report> {
    let mut s = State { p, store: Store::open(p.repo_dir, p.state.clone())?, tasks: BTreeMap::new(), report: Report::default() };
    for path in s.store.list("tasks/") {
        if let Some(t) = s.store.get::<Task>(&path)? {
            s.tasks.insert(t.id.clone(), t);
        }
    }
    for o in &p.outbounds {
        if let Some(c) = s.store.get::<serde_json::Value>(&format!("cache/{}.json", file_key(o.name())))? {
            o.restore(c);
        }
    }
    s.results()?;
    s.receive();
    s.stale()?;
    s.post()?;
    s.publish();
    s.save()
}

impl State<'_, '_> {
    fn log(&mut self, what: &str, task: Option<&str>, item: Option<&ItemRef>, author: Option<&str>, detail: impl Into<String>) {
        self.report.log.push(LogLine { at: self.p.now, what: what.into(), task: task.map(String::from), item: item.map(|i| i.0.clone()), author: author.map(String::from), detail: detail.into() });
    }

    fn apply(&mut self, id: &str, ev: Event) -> Result<()> {
        let rules = self.p.cfg.policy.rules();
        if let Some(t) = self.tasks.get_mut(id) {
            t.apply(ev, rules, self.p.now)?;
        }
        Ok(())
    }

    /// Verified results become commits and pull requests, and the tasks hear about them.
    fn results(&mut self) -> Result<()> {
        let (cfg, p) = (self.p.cfg, self.p);
        let trusted = cfg.trusted(p.key);
        let mut o = crate::pr_flow::Options::new(p.repo_dir, &cfg.base);
        o.max_open = cfg.max_open;
        o.protected.extend(cfg.protect.iter().cloned());
        for t in self.tasks.values() {
            if let Some(n) = t.request_issue() {
                o.closes.insert(t.id.clone(), n);
            }
            o.titles.insert(t.id.clone(), t.title.clone());
        }
        self.report.pull_requests = crate::pr_flow::run(p.queue, &cfg.repo, &trusted, &o)?;

        let running: Vec<(String, u32, String, u64)> = self.tasks.values().filter_map(|t| match t.state {
            super::task::State::Running { attempt } => t.attempts.last().and_then(|a| a.issue.map(|i| (t.id.clone(), attempt, a.manifest_id.clone(), i))),
            _ => None,
        }).collect();
        for (id, attempt, mid, issue) in running {
            let r = match p.queue.attempt_report(&trusted, issue, &mid) {
                Ok(r) => r,
                Err(e) => {
                    // One unreadable task issue (deleted, edited) must not stop every pass.
                    self.log("error", Some(&id), None, None, format!("attempt {attempt} (issue #{issue}): {e}"));
                    self.report.errors.push(format!("{id}: {e}"));
                    continue;
                }
            };
            let Some((kind, kv, text)) = r.handled else { continue };
            let pr = kv.get("pr").and_then(|n| n.parse().ok());
            let first = text.lines().find(|l| l.starts_with("Not turned into")).unwrap_or("").to_string();
            let outcome = match (kind.as_str(), pr) {
                ("skip", _) => format!("refused: {}", first.trim_start_matches("Not turned into a pull request: ").trim_end_matches('.')),
                (_, Some(_)) => "pull request".into(),
                _ if text.contains("changes nothing") => "no change".into(),
                _ => "text only".into(),
            };
            let result = AttemptResult {
                output: r.result.as_ref().map(|b| b.output.clone()).unwrap_or_default(),
                tokens_used: r.result.as_ref().map_or(0, |b| b.tokens_used),
                runner: r.result.as_ref().map(|b| b.runner_id.clone()).unwrap_or_default(),
                outcome: outcome.clone(),
            };
            self.log("result", Some(&id), None, None, format!("attempt {attempt}: {outcome}"));
            self.apply(&id, Event::Result { attempt, result, pr })?;
        }
        Ok(())
    }

    fn receive(&mut self) {
        for ib in self.p.inbounds.clone() {
            let path = format!("cursors/{}.json", file_key(ib.name()));
            let cursor = match self.store.get::<Cursor>(&path) {
                Ok(c) => c.unwrap_or_default(),
                Err(e) => {
                    self.report.errors.push(format!("{}: {e}", ib.name()));
                    continue;
                }
            };
            let (items, next) = match ib.receive(&cursor) {
                Ok(x) => x,
                Err(e) => {
                    self.report.errors.push(format!("{}: {e}", ib.name()));
                    continue;
                }
            };
            for item in items {
                if let Err(e) = self.handle(item) {
                    self.report.errors.push(format!("{}: {e}", ib.name()));
                }
            }
            if let Err(e) = self.store.put(&path, &next) {
                self.report.errors.push(format!("{}: {e}", ib.name()));
            }
        }
    }

    fn resolve(&self, refs: &[ItemRef]) -> Option<String> {
        self.tasks.values().find(|t| refs.iter().any(|r| t.links.contains(r))).map(|t| t.id.clone())
    }

    /// How an author appears in everything toto writes. GitHub logins are public already. A mail
    /// address never is: a pre-approved sender is their configured `name`, or a pseudonym keyed by
    /// the project's signing key (stable, and not computable from a guessed address without the
    /// key); an unknown sender is their domain.
    fn public_name(&self, a: &Author) -> String {
        if a.address.starts_with("github:") {
            return a.address.clone();
        }
        public_name(&self.p.cfg.policy, self.p.key, &a.address)
    }

    fn usage_path(author: &str) -> String {
        format!("senders/{}.json", file_key(author))
    }

    fn used_today(&self, author: &str) -> u32 {
        let today = self.p.now.format("%Y-%m-%d").to_string();
        self.store.get::<Usage>(&Self::usage_path(author)).ok().flatten().filter(|u| u.day == today).map_or(0, |u| u.count)
    }

    fn count(&mut self, author: &Author, who: &str) -> Result<()> {
        if self.p.cfg.policy.is_maintainer(author) {
            return Ok(());
        }
        let today = self.p.now.format("%Y-%m-%d").to_string();
        let count = self.used_today(who) + 1;
        self.store.put(&Self::usage_path(who), &Usage { day: today, count })
    }

    fn handle(&mut self, item: Received) -> Result<()> {
        let policy = &self.p.cfg.policy;
        let rules = policy.rules();
        let now = self.p.now;
        match item {
            Received::Message { id, thread, author, subject, body } => {
                let who = self.public_name(&author);
                if self.tasks.values().any(|t| t.seen.contains(&id)) {
                    return Ok(()); // a repeated delivery
                }
                let resolved = thread.as_ref().and_then(|th| self.resolve(&th.0));
                if let Some(tid) = resolved {
                    let t = &self.tasks[&tid];
                    let ask = super::policy::Ask { kind: t.kind.clone(), estimate: t.estimate, unknown_kind: None };
                    let decision = policy.decide_message(&author, &ask, self.used_today(&who));
                    let approved = match &decision {
                        Decision::Ignore(why) => {
                            self.log("ignore", Some(&tid), Some(&id), Some(&who), why.clone());
                            return Ok(());
                        }
                        Decision::Hold(why) => {
                            self.log("hold", Some(&tid), Some(&id), Some(&who), format!("refinement: {why}"));
                            false
                        }
                        Decision::Accept => {
                            self.log("accept", Some(&tid), Some(&id), Some(&who), "refinement");
                            self.count(&author, &who)?;
                            true
                        }
                    };
                    let turn = Turn { source: id, role: Role::Refinement, author: who.clone(), text: body, approved, at: now };
                    return self.apply(&tid, Event::Refine(turn));
                }
                if thread.as_ref().is_some_and(|th| !th.0.is_empty() && th.0.iter().all(|r| r.0.starts_with("github:pr:"))) {
                    return Ok(()); // a comment on a pull request that is not a toto task's
                }
                let tid = super::task::task_id_for(&id);
                if self.tasks.contains_key(&tid) {
                    return Ok(());
                }
                let ask = policy.ask(&author, subject.as_deref(), &body);
                let decision = policy.decide_message(&author, &ask, self.used_today(&who));
                let (approved, note) = match decision {
                    Decision::Ignore(why) => {
                        self.log("ignore", None, Some(&id), Some(&who), why);
                        return Ok(());
                    }
                    Decision::Hold(why) => {
                        self.log("hold", Some(&tid), Some(&id), Some(&who), why.clone());
                        (false, Some(why))
                    }
                    Decision::Accept => {
                        self.log("accept", Some(&tid), Some(&id), Some(&who), format!("new task, kind {}, estimate {}", ask.kind, ask.estimate));
                        self.count(&author, &who)?;
                        (true, None)
                    }
                };
                let title = subject.as_deref().map(clean_title).filter(|t| !t.is_empty()).or_else(|| body.lines().map(str::trim).find(|l| !l.is_empty()).map(clean_title)).unwrap_or_else(|| "untitled request".into());
                let turn = Turn { source: id, role: Role::Request, author: who.clone(), text: body, approved, at: now };
                let mut t = Task::new(&self.p.cfg.project_id, turn, &ask.kind, &title, ask.estimate, note, now);
                t.start(rules);
                self.tasks.insert(tid, t);
                Ok(())
            }
            Received::Skipped { id, from, reason } => {
                let who = if from.contains('@') { public_name(&self.p.cfg.policy, self.p.key, &from) } else { from };
                self.log("ignore", None, Some(&id), Some(&who), reason);
                Ok(())
            }
            Received::Signal { id, thread, author, kind } => {
                let who = self.public_name(&author);
                let Some(tid) = self.resolve(&thread.0) else { return Ok(()) };
                if self.tasks[&tid].seen.contains(&id) {
                    return Ok(());
                }
                let ev = match kind {
                    SignalKind::Approve => Event::Approve,
                    SignalKind::Done => Event::Done,
                    SignalKind::Reopen => Event::Reopen,
                    SignalKind::Cancel => Event::Cancel,
                };
                // A signal that would change nothing (toto's own closing of an issue, seen on the
                // next pass) is dropped without a log line.
                let mut probe = self.tasks[&tid].clone();
                probe.apply(ev.clone(), rules, now)?;
                if probe == self.tasks[&tid] {
                    return Ok(());
                }
                match policy.decide_signal(&author, &who, kind, &self.tasks[&tid]) {
                    Decision::Accept => {
                        self.log("signal", Some(&tid), Some(&id), Some(&who), format!("{kind:?}"));
                        self.apply(&tid, ev)?;
                        if let Some(t) = self.tasks.get_mut(&tid) {
                            t.seen.insert(id);
                        }
                    }
                    Decision::Hold(why) | Decision::Ignore(why) => self.log("ignore", Some(&tid), Some(&id), Some(&who), why),
                }
                Ok(())
            }
        }
    }

    fn stale(&mut self) -> Result<()> {
        let days = i64::from(self.p.cfg.policy.stale_days);
        let ids: Vec<String> = self.tasks.values().filter(|t| !t.state.is_terminal() && !matches!(t.state, super::task::State::Running { .. }) && self.p.now - t.updated > chrono::Duration::days(days)).map(|t| t.id.clone()).collect();
        for id in ids {
            self.log("stale", Some(&id), None, None, format!("no activity for {days} days"));
            self.apply(&id, Event::Stale)?;
        }
        Ok(())
    }

    /// Posts the attempts that are due, oldest task first, within the project's daily cap.
    fn post(&mut self) -> Result<()> {
        let today = self.p.now.date_naive();
        let mut posted = self.tasks.values().flat_map(|t| &t.attempts).filter(|a| a.posted_at.date_naive() == today).count() as u32;
        let mut due: Vec<(DateTime<Utc>, String)> = self.tasks.values().filter(|t| t.state == super::task::State::Queued).map(|t| (t.created, t.id.clone())).collect();
        if due.is_empty() {
            return Ok(());
        }
        due.sort();
        let trusted = self.p.cfg.trusted(self.p.key);
        let index = self.p.queue.task_index(&trusted)?;
        for (_, id) in due {
            if posted >= self.p.cfg.policy.daily_attempt_cap {
                self.log("cap", Some(&id), None, None, format!("{posted} attempts posted today, the project's daily cap; it waits for tomorrow"));
                continue;
            }
            match self.post_attempt(&id, &index) {
                Ok((mid, issue)) => {
                    self.log("post", Some(&id), None, None, format!("{mid} as issue #{issue}"));
                    self.report.posted.push(mid.clone());
                    self.apply(&id, Event::Posted { manifest_id: mid, issue: Some(issue) })?;
                    posted += 1;
                }
                Err(e) => {
                    self.log("error", Some(&id), None, None, format!("could not post the next attempt: {e}"));
                    self.report.errors.push(format!("{id}: {e}"));
                }
            }
        }
        Ok(())
    }

    fn post_attempt(&self, id: &str, index: &HashMap<String, (u64, bool)>) -> Result<(String, u64)> {
        let (cfg, p) = (self.p.cfg, self.p);
        let t = &self.tasks[id];
        let n = t.attempts.len() as u32 + 1;
        let mid = t.manifest_id(n);
        if let Some((issue, _)) = index.get(&mid) {
            return Ok((mid, *issue)); // posted by a pass that failed before saving
        }
        let kind = cfg.policy.kinds.get(&t.kind).ok_or_else(|| Error::Policy(format!("kind `{}` is no longer configured", t.kind)))?;
        let dir = p.repo_dir;
        super::git::git(dir, &["fetch", "-q", "origin", &cfg.base])?;
        let branch = t.branch("toto/");
        let rev = if n > 1 && super::git::remote_has(dir, &branch)? {
            super::git::git(dir, &["fetch", "-q", "origin", &format!("+refs/heads/{branch}:refs/remotes/origin/{branch}")])?;
            format!("refs/remotes/origin/{branch}")
        } else {
            format!("refs/remotes/origin/{}", cfg.base)
        };
        let records = super::git::bundle(dir, &rev, crate::archive::Limits::new(cfg.max_input_bytes))?;
        let bytes = crate::archive::to_bytes(&records).map_err(Error::Schema)?;
        let inputs = p.queue.upload_bundle(&bytes)?;
        let manifest = TaskManifest {
            id: mid.clone(),
            project_id: cfg.project_id.clone(),
            kind: t.kind.clone(),
            inputs,
            prompt: super::prompt::build(t, n, cfg.max_prompt_chars),
            tool_requirements: kind.tool_requirements.clone(),
            sandbox_profile: kind.sandbox_profile.clone().unwrap_or_default(),
            cost_estimate: t.estimate,
            output_schema: OutputSchema { format: kind.format.clone(), max_bytes: kind.max_output_bytes, max_artifact_bytes: kind.max_artifact_bytes },
            redundancy: 1,
            task: Some(t.id.clone()),
            attempt: Some(n),
        };
        let issue = p.queue.post_task(&manifest.sign(p.key)?)?;
        Ok((mid, issue))
    }

    /// Shows every task whose view changed on every outbound. A failing outbound does not stop
    /// the pass; the next one retries it.
    fn publish(&mut self) {
        let rules = self.p.cfg.policy.rules();
        let ids: Vec<String> = self.tasks.keys().cloned().collect();
        for id in ids {
            for o in self.p.outbounds.clone() {
                let t = &self.tasks[&id];
                let view = t.view(rules); // fresh: an earlier outbound may have added a link
                let fp = view.fingerprint();
                if t.published.get(o.name()) == Some(&fp) {
                    continue;
                }
                match o.publish(&view) {
                    Ok(link) => {
                        let t = self.tasks.get_mut(&id).expect("listed");
                        if let Some(l) = link {
                            t.link(l);
                        }
                        t.published.insert(o.name().into(), fp);
                        self.report.published += 1;
                    }
                    Err(e) => {
                        self.log("error", Some(&id), None, None, format!("{}: {e}", o.name()));
                        self.report.errors.push(format!("{} ({id}): {e}", o.name()));
                    }
                }
            }
        }
    }

    fn save(mut self) -> Result<Report> {
        for t in self.tasks.values() {
            self.store.put(&format!("tasks/{}.json", t.id), t)?;
        }
        for o in &self.p.outbounds {
            if let Some(c) = o.cache() {
                self.store.put(&format!("cache/{}.json", file_key(o.name())), &c)?;
            }
        }
        let log = format!("log/{}.jsonl", self.p.now.format("%Y-%m-%d"));
        for l in &self.report.log {
            self.store.append(&log, &serde_json::to_string(l)?);
        }
        let oldest = (self.p.now - chrono::Duration::days(i64::from(self.p.cfg.log_days))).format("log/%Y-%m-%d.jsonl").to_string();
        for old in self.store.list("log/").into_iter().filter(|p| *p < oldest) {
            self.store.remove(&old);
        }
        let msg = format!("toto sync: {} posted, {} published, {} log lines", self.report.posted.len(), self.report.published, self.report.log.len());
        self.report.commit = self.store.commit_and_push(&msg)?;
        Ok(self.report)
    }
}

/// Secrets and endpoints the CLI hands to [`sync_repo`].
pub struct Secrets {
    pub api: String,
    /// For the queue repository: issues, comments, pull requests, release assets.
    pub github_token: String,
    /// For the Projects board, when configured (`projects_v2.token_env`).
    pub projects_token: Option<String>,
    /// For the inbox, when configured (`email.password_env`).
    pub imap_password: Option<String>,
    /// For `state_repo`, when configured (`TOTO_STATE_TOKEN`).
    pub state_token: Option<String>,
}

/// One pass with the connectors `.toto/intake.toml` configures.
pub fn sync_repo(cfg: &IntakeConfig, repo_dir: &Path, key: &SigningKey, secrets: &Secrets, now: DateTime<Utc>) -> Result<Report> {
    let queue = GitHubQueue::new(&secrets.api, &cfg.repo, crate::github_queue::DEFAULT_LABEL, Some(secrets.github_token.clone()));
    let issues = super::github::GitHubIssues::new(&queue, &cfg.github.label);
    let board = match &cfg.projects_v2 {
        Some(c) => {
            let token = secrets.projects_token.clone().ok_or_else(|| Error::Policy(format!("projects_v2 is configured but ${} is not set (a token with the `project` scope)", c.token_env)))?;
            Some(super::projects_v2::ProjectsV2::new(c.clone(), GitHubQueue::new(&secrets.api, &cfg.repo, crate::github_queue::DEFAULT_LABEL, Some(token)), &queue))
        }
        None => None,
    };
    let imap = match &cfg.email {
        Some(e) => Some(super::imap::Imap {
            host: e.imap_host.clone(),
            port: e.imap_port,
            user: e.user.clone().unwrap_or_else(|| e.address.clone()),
            password: secrets.imap_password.clone().ok_or_else(|| Error::Policy(format!("email is configured but ${} is not set", e.password_env)))?,
            folder: e.folder.clone(),
            plaintext: false,
        }),
        None => None,
    };
    let mail = cfg.email.as_ref().zip(imap.as_ref()).map(|(c, i)| super::email::EmailInbound { cfg: c.clone(), source: i });
    let mut inbounds: Vec<&dyn Inbound> = vec![];
    let mut outbounds: Vec<&dyn Outbound> = vec![];
    if cfg.github.requests {
        inbounds.push(&issues);
    }
    if let Some(m) = &mail {
        inbounds.push(m);
    }
    if cfg.github.status {
        outbounds.push(&issues);
    }
    if let Some(b) = &board {
        outbounds.push(b);
    }
    if cfg.state_repo.as_deref().is_some_and(|r| !r.starts_with('/')) && secrets.state_token.is_none() {
        return Err(Error::Policy("state_repo is configured but $TOTO_STATE_TOKEN is not set (a token that can push to it)".into()));
    }
    let state = cfg.state_location(secrets.state_token.clone());
    run(&Pass { cfg, queue: &queue, key, repo_dir, inbounds, outbounds, state, now })
}

/// The public name of a mail address (see `State::public_name`).
pub fn public_name(policy: &IntakePolicy, key: &SigningKey, address: &str) -> String {
    let address = address.to_lowercase();
    match policy.sender(&address) {
        Some(s) => s.name.clone().unwrap_or_else(|| {
            use sha2::{Digest, Sha256};
            let salt = Sha256::digest([b"toto sender name\0".as_slice(), &key.to_bytes()].concat());
            let h = Sha256::digest([salt.as_slice(), address.as_bytes()].concat());
            format!("sender-{}", &hex::encode(h)[..8])
        }),
        None => format!("an unknown sender at {}", address.rsplit_once('@').map_or("?", |x| x.1)),
    }
}
