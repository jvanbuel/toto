# 16. Task intake, refinement and tracking through Inbound and Outbound connectors

- Status: Accepted (implemented 2026-10-07: `src/intake/`, `docs/intake.md`)
- Date: 2026-10-07
- Relates to: ADR 3 (signing), ADR 6 (redundancy), ADR 13; plan in `docs/plans/intake-and-tracking.md`

## Context

Today a project creates a task with `toto post-task`: a maintainer writes a manifest, signs it with the project key and posts it as an issue. Each result becomes its own pull request, and the conversation ends there. Two things are missing:

- **Easy intake.** People who are not maintainers at a terminal, such as a maintainer on their phone or a trusted collaborator, should be able to ask for work in an ordinary way: an email, or an issue form.
- **Feedback and visibility.** A result is rarely final. Someone reads the PR and says "also handle the empty case". That comment is a refinement of the task, no different in kind from the original prompt. Progress should also be visible where the project already tracks work: a GitHub Projects board, Azure DevOps, and so on.

All of this happens on the **project side**, in the project's own automation, which already holds the project's signing key. Contributors' runners are unchanged: they still see only signed manifests.

## Decision

### Two traits, split by direction

```rust
/// Where requests and feedback come from: an inbox, issue comments, a board.
pub trait Inbound {
    fn name(&self) -> &str;
    /// What arrived after `since`, and the cursor to pass next time. Never decides approval: it
    /// reports facts. The cursor is opaque to core (comment ids, an IMAP UID) and is stored with the
    /// rest of the state, so a connector keeps nothing itself.
    fn receive(&self, since: &Cursor) -> Result<(Vec<Received>, Cursor)>;
}

/// Where a task's state is shown. Core calls it only when the task's view changed.
pub trait Outbound {
    fn name(&self) -> &str;
    fn publish(&self, task: &TaskView) -> Result<Option<ItemRef>>;
    fn cache(&self) -> Option<serde_json::Value> { None }   // ids worth keeping between passes
    fn restore(&self, _: serde_json::Value) {}
}

pub enum Received {
    /// `thread` is what the connector saw (an issue number; `In-Reply-To` and `References`); core
    /// resolves it against the tasks' links. Resolved: a refinement. Absent: a new task.
    Message { id: ReceivedRef, thread: Option<ThreadRef>, author: Author, subject: Option<String>, body: String },
    /// An explicit state change by a person, or by the platform (a merged pull request).
    Signal { id: ReceivedRef, thread: ThreadRef, author: Author, kind: SignalKind },
    /// Something the connector will not report as a message (automated mail), so the log says why.
    Skipped { id: ReceivedRef, from: String, reason: String },
}

pub enum SignalKind { Approve, Done, Reopen, Cancel }

pub struct Author {
    pub address: String,              // `github:<login>` or a mail address
    pub verified: Verification,       // None | Dkim | SecretAddress | Both | Platform
    pub maintainer: bool,             // a platform fact: write access to the repository
    pub tag_sha256: Option<String>,   // hash of a plus-address tag; core compares it with the sender's
}
```

- A connector may implement one trait or both. GitHub issues implement both, email only `Inbound`, and a Projects board only `Outbound`. One task can be linked to several items: the email thread it came from, its board card, its PR.
- Connectors report facts: who sent it, how that was verified, and what it says. **Core policy decides** whether it becomes a task. No connector can approve anything by itself.

### Tasks and attempts

- A **task** is the unit people talk about. An **attempt** is one signed manifest that runners execute. A task has one or more attempts.
- Attempt *n+1* is created from a refinement. Its prompt carries the original request, every refinement so far, and the previous attempt's output. Its input bundle is the task branch as it stands, so the agent continues from its own previous work instead of starting over.
- Lifecycle: `Draft → Queued → Running(n) → AwaitingFeedback(n) → Queued (refinement) | Done | Cancelled`.
- **One branch and one PR per task** (`toto/<task>`). Each attempt adds a commit to it. Today it is one PR per result. Attempt ids are deterministic (`<task>-a<n>`), so a pass that finds attempt *n* already posted never posts it again.
- On GitHub a task is three things: the request issue (what the person asked), one task issue per attempt (the signed manifest, as today), and the PR. The request issue's status comment links all of them, and the PR body says `Closes #<request>` so a merge closes the request through GitHub itself.
- Redundancy (ADR 6) is not enforced by anything yet: `pr_flow` applies the first verified result and ignores `redundancy`. Attempts are posted with `redundancy: 1` until ADR 6 is implemented, so a project does not pay two contributors for a comparison nobody makes.
- "Done" is an explicit signal: a merged PR, a closed issue, a `/done` comment, or a "done" reply. Silence is not done; after a configurable idle period the task is closed as stale.

### Approval

- A new task or a refinement becomes an attempt only if the policy approves it. Approval comes either from a **pre-approved sender** within their limits, or from an `Approve` signal by a maintainer.
- Pre-approved email senders are listed in the project's intake config, each with a verification requirement (`dkim`, `secret-address` or `both`) and limits: allowed kinds, maximum cost estimate and tasks per day. There is no undo window in v1: without a reply mail (deferred, see below) the sender could not use one, and it only delays legitimate work.
- DKIM is read from the receiving provider's `Authentication-Results` header for the configured inbox (`dkim=pass` with a `header.d` aligned to the sender's domain). toto does not verify DKIM signatures itself in v1. The mail must also name the inbox in `To` or `Cc`, so a forwarded mail that still passes DKIM does not count. The secret address is a plus-address (`toto+<secret>@…`) known only to that sender; the config, which is public, holds only its hash, and the secret must be at least 128 bits.
- Automated mail (`Auto-Submitted` other than `no`, `Precedence: bulk|list|junk`, and mail from the inbox's own address) is ignored and never answered, so two robots cannot loop.
- Refinements that arrive while an attempt is running are batched into the next attempt. A task has an attempt cap (default 5); beyond it, a maintainer must approve each further attempt.
- The kind of a task comes from a subject tag (`[docs]`), or else the sender's default kind. Its cost estimate is the default for that kind unless the request says otherwise; the policy limits apply to the estimate.

### Where it runs

`toto project sync` is one pass of: receive from every inbound, apply policy, sign and post attempts, turn verified results into commits on the task branch and PR, and publish every changed task to every outbound. It replaces `results-to-pr` (which stays as an alias) and runs as the project's scheduled job. The job runs on a fresh machine each time, so it keeps no local state: everything it needs lives on a dedicated `toto-state` branch of the queue repository (`tasks/<id>.json`, per-sender daily counts, inbound cursors, cached board ids), committed at the end of each pass. The default branch is never written. A non-fast-forward push of that branch means another pass ran concurrently; the pass aborts and the next one redoes the work, which is safe because every step is idempotent. No new server and no database are needed.

## Consequences

- People can ask for work by email, and feedback flows back as refinements, without contributors' runners changing at all. Every attempt is still a manifest signed with the project's key.
- The manifest gains optional `task` and `attempt` fields, inside the signed payload, so a result can be tied to its task and attempt without trusting an issue body. Old runners ignore unknown fields. Old manifests without the fields are tasks with one attempt.
- Each pre-approved sender is a credential: whoever controls that mailbox, or learns the secret address, can spend contributors' donated tokens on this project within the sender's limits. The per-sender and project-wide limits bound that damage, and the project owner guide must say so plainly.
- The prompt of a refinement attempt contains text from people other than maintainers. That text was already possible through `post-task`; now it arrives faster. It is shown in fences, it is never executable configuration, and the agent's sandbox is unchanged.
- Board connectors only display state, so a board that is wrong or is edited by hand cannot cause work to run. Moving a card can at most send a `Signal`, which goes through the same policy.

## As built

Where the implementation differs from the first sketch of this record, and why:

- A `Signal` carries a `ThreadRef`, not an `ItemRef`: a "done" reply by mail only knows the thread it answers.
- `Received::Skipped` exists so that automated or oversized mail shows up in the sync log with its reason, instead of disappearing.
- `Author.maintainer` is a fact the platform reports (repository permission). Core only believes it with `Verification::Platform`.
- The GitHub inbound's cursor moves by GitHub's own `updated_at` times, not the job's clock, so a pass with nothing new commits nothing.
- A signal that would change nothing is dropped silently. Toto's own closing of an issue comes back as such a signal on the next pass.
- `TaskView` is `id, title, kind, state, attempt, attempt_cap, tokens_used, requester, request, latest_output, note, pr, attempt_issues, links`. Its fingerprint leaves out `links`, because publishing adds links.
- Comments on a finished task reopen it ("a comment means it is not done").

## Open questions

- Replying to email: confirmations and "result ready" mails need an SMTP sender, which needs its own credential and its own anti-loop rules. Deferred until after the first email intake works.
