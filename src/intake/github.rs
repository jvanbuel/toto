//! GitHub issues as an [`Inbound`] and an [`Outbound`].
//!
//! In: a new issue with the request label (the issue form applies it) is a request; a comment on a
//! request issue or on a task's pull request is a refinement; `/approve`, `/done`, `/reopen` and
//! `/cancel` are commands; closing, reopening and merging are signals. Authors are authenticated by
//! GitHub, and whether one is a maintainer is their permission on the repository, never anything
//! they wrote. Bots and toto's own comments (they start with a `<!-- toto:` marker) are ignored.
//!
//! Out: one status comment per request issue, edited in place; a request that came another way
//! (email) is mirrored to an issue so maintainers can see it, discuss it and `/approve` it; the
//! request issue is closed when the task ends (and the pull request, when it was cancelled).

use super::task::State;
use super::{Author, Cursor, Inbound, ItemRef, Outbound, Received, SignalKind, TaskView, ThreadRef};
use crate::github_queue::{is_toto_text, GitHubQueue, IssueInfo, DEFAULT_LABEL};
use crate::pr_flow::fenced;
use crate::Result;
use chrono::{DateTime, Utc};

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

pub struct GitHubIssues<'a> {
    q: &'a GitHubQueue,
    label: String,
    maintainers: Mutex<HashMap<String, bool>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Seen {
    /// The highest comment id handled on this issue.
    #[serde(default)]
    c: u64,
    #[serde(default)]
    closed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GhCursor {
    #[serde(default)]
    since: Option<DateTime<Utc>>,
    #[serde(default)]
    items: BTreeMap<u64, Seen>,
}

/// How far before the newest change seen the next listing starts, in case GitHub lists a change
/// late. Anything seen twice is recognised by its id.
const OVERLAP_MINUTES: i64 = 10;

impl<'a> GitHubIssues<'a> {
    pub fn new(q: &'a GitHubQueue, label: &str) -> Self {
        Self { q, label: label.into(), maintainers: Mutex::default() }
    }

    fn maintainer(&self, login: &str) -> Result<bool> {
        if let Some(m) = self.maintainers.lock().unwrap().get(login) {
            return Ok(*m);
        }
        let m = matches!(self.q.permission(login)?.as_str(), "admin" | "maintain" | "write");
        self.maintainers.lock().unwrap().insert(login.into(), m);
        Ok(m)
    }

    fn author(&self, user: &crate::github_queue::User) -> Result<Author> {
        Ok(Author::platform(&user.login, self.maintainer(&user.login)?))
    }

    /// Closing, reopening and merging, done on GitHub by someone GitHub allowed to: the issue's
    /// author, a triager, or (for toto's pull requests) a maintainer. Any of them may end a task.
    fn platform_event(&self) -> Author {
        Author::platform("(github)", true)
    }

    fn item(i: &IssueInfo) -> ItemRef {
        ItemRef::new(format!("github:{}:{}", if i.is_pull() { "pr" } else { "issue" }, i.number))
    }
}

impl Inbound for GitHubIssues<'_> {
    fn name(&self) -> &str {
        "github"
    }

    fn receive(&self, since: &Cursor) -> Result<(Vec<Received>, Cursor)> {
        let mut cur: GhCursor = serde_json::from_value(since.0.clone()).unwrap_or_default();
        let mut issues: Vec<IssueInfo> = self.q.list_issues(&self.label, "all", cur.since)?.into_iter().filter(|i| !i.is_pull()).collect();
        issues.extend(self.q.list_issues(DEFAULT_LABEL, "all", cur.since)?.into_iter().filter(IssueInfo::is_pull));
        let mut out = vec![];
        // The next listing starts a little before the newest change GitHub reported (its clock, not
        // ours), so the cursor only moves when something did.
        let newest = issues.iter().filter_map(|i| i.updated_at).max();
        for i in issues {
            let me = Self::item(&i);
            let thread = ThreadRef(vec![me.clone()]);
            let seen = cur.items.get(&i.number).cloned();
            let mut entry = seen.clone().unwrap_or_default();
            match seen {
                None if !i.is_pull() => {
                    let user = i.user.clone().unwrap_or_default();
                    let body = i.body.clone().unwrap_or_default();
                    // Mirrors toto made, closed issues found late and bots' issues are not requests.
                    if !i.closed() && !is_toto_text(&body) && !user.is_bot() {
                        out.push(Received::Message { id: me.clone(), thread: None, author: self.author(&user)?, subject: Some(i.title.clone()), body });
                    }
                    entry.closed = i.closed();
                }
                _ => {
                    if i.closed() && !entry.closed {
                        let kind = if !i.is_pull() || i.merged() { SignalKind::Done } else { SignalKind::Cancel };
                        let stamp = i.updated_at.map_or(0, |t| t.timestamp());
                        out.push(Received::Signal { id: ItemRef::new(format!("{me}:closed:{stamp}")), thread: thread.clone(), author: self.platform_event(), kind });
                    } else if !i.closed() && entry.closed {
                        let stamp = i.updated_at.map_or(0, |t| t.timestamp());
                        out.push(Received::Signal { id: ItemRef::new(format!("{me}:reopened:{stamp}")), thread: thread.clone(), author: self.platform_event(), kind: SignalKind::Reopen });
                    }
                    entry.closed = i.closed();
                }
            }
            if i.comments > 0 {
                for c in self.q.issue_comments(i.number)? {
                    if c.id <= entry.c {
                        continue;
                    }
                    entry.c = c.id;
                    let user = c.user.clone().unwrap_or_default();
                    if user.is_bot() || is_toto_text(&c.body) || c.body.trim().is_empty() {
                        continue;
                    }
                    let id = ItemRef::new(format!("github:comment:{}", c.id));
                    let author = self.author(&user)?;
                    out.push(match SignalKind::from_command(&c.body) {
                        Some(kind) => Received::Signal { id, thread: thread.clone(), author, kind },
                        None => Received::Message { id, thread: Some(thread.clone()), author, subject: None, body: c.body },
                    });
                }
            }
            cur.items.insert(i.number, entry);
        }
        if let Some(t) = newest {
            let next = t - chrono::Duration::minutes(OVERLAP_MINUTES);
            cur.since = Some(cur.since.map_or(next, |s| s.max(next)));
        }
        Ok((out, Cursor(serde_json::to_value(cur)?)))
    }
}

/// The status comment's first line; the task id ties it to its task.
fn status_marker(task: &str) -> String {
    format!("<!-- toto:status task={task} -->")
}

pub fn status_body(v: &TaskView) -> String {
    let attempt = match v.attempt {
        0 => String::new(),
        n => format!(" · attempt {n} of {}", v.attempt_cap.max(n)),
    };
    let mut s = format!("{}\n**toto** · task `{}` · **{}**{attempt} · {} tokens used\n", status_marker(&v.id), v.id, v.state.label(), v.tokens_used);
    if let Some(n) = &v.note {
        s.push_str(&format!("\n> {}\n", n.replace('\n', " ")));
    }
    if let Some(pr) = v.pr {
        s.push_str(&format!("\nPull request: #{pr}\n"));
    }
    if !v.attempt_issues.is_empty() {
        let list: Vec<String> = v.attempt_issues.iter().enumerate().map(|(k, n)| format!("#{n} (attempt {})", k + 1)).collect();
        s.push_str(&format!("Attempts: {}\n", list.join(", ")));
    }
    if let Some(out) = &v.latest_output
        && !out.trim().is_empty()
    {
        s.push_str(&format!("\n<details><summary>Latest output</summary>\n\n{}\n\n</details>\n", fenced(out, 3000)));
    }
    if !v.state.is_terminal() {
        s.push_str("\nAny comment here or on the pull request refines the task. Maintainers: `/approve` runs what waits, `/done` ends it, `/cancel` drops it.\n");
    }
    s
}

impl GitHubIssues<'_> {
    /// The task's mirror issue: found by its marker if a pass that made it lost its state, else made.
    fn mirror(&self, v: &TaskView) -> Result<u64> {
        let mark = format!("<!-- toto:mirror task={} -->", v.id);
        if let Some(i) = self.q.list_issues(&self.label, "all", None)?.into_iter().find(|i| i.body.as_deref().is_some_and(|b| b.starts_with(&mark)) && i.user.as_ref().is_some_and(|u| u.is_bot())) {
            return Ok(i.number);
        }
        let body = format!(
            "{mark}\nRequested by {} (not on GitHub). Comment here to refine it; a maintainer's `/approve` runs it if it waits.\n\n{}",
            v.requester,
            fenced(&v.request, 6000)
        );
        self.q.create_issue(&format!("[toto] {}", v.title), &body, &[&self.label])
    }

    fn upsert_status(&self, issue: u64, v: &TaskView) -> Result<()> {
        let mark = status_marker(&v.id);
        let body = status_body(v);
        let comments = self.q.issue_comments(issue)?;
        let mine: Vec<_> = comments.iter().filter(|c| c.body.starts_with(&mark)).collect();
        // Prefer a bot's: with the workflow token that is toto, and nobody else can be a bot.
        let existing = mine.iter().rev().find(|c| c.user.as_ref().is_some_and(|u| u.is_bot())).or(mine.last());
        match existing {
            Some(c) if c.body == body => Ok(()),
            Some(c) => self.q.edit_comment(c.id, &body).or_else(|_| self.q.comment(issue, &body)),
            None => self.q.comment(issue, &body),
        }
    }
}

impl Outbound for GitHubIssues<'_> {
    fn name(&self) -> &str {
        "github"
    }

    fn publish(&self, v: &TaskView) -> Result<Option<ItemRef>> {
        let issue = match v.request_issue() {
            Some(n) => n,
            None => self.mirror(v)?,
        };
        self.upsert_status(issue, v)?;
        let info = self.q.issue(issue)?;
        match (v.state.is_terminal(), info.closed()) {
            (true, false) => self.q.close_issue(issue)?,
            (false, true) => self.q.reopen_issue(issue)?,
            _ => {}
        }
        if v.state == State::Cancelled
            && let Some(pr) = v.pr
            && !self.q.issue(pr)?.closed()
        {
            self.q.close_pull(pr)?;
        }
        Ok(Some(ItemRef::new(format!("github:issue:{issue}"))))
    }
}
