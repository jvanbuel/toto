# 16. Task intake, refinement and tracking through Inbound and Outbound connectors

- Status: Proposed
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
    /// What arrived since the last acknowledge. Never decides approval: it reports facts.
    fn receive(&self) -> Result<Vec<Received>>;
    /// Mark items as taken so `receive` does not return them again.
    fn acknowledge(&self, taken: &[ReceivedRef]) -> Result<()>;
}

/// Where a task's state is shown: a board, a work item. Idempotent: publishing the same view twice is a no-op.
pub trait Outbound {
    fn publish(&self, task: &TaskView) -> Result<ItemRef>;
}

pub enum Received {
    /// No thread: a new task. A thread: a refinement of the task the thread belongs to.
    Message { id: ReceivedRef, thread: Option<ItemRef>, author: Author, subject: Option<String>, body: String },
    /// An explicit state change by a person.
    Signal { id: ReceivedRef, item: ItemRef, author: Author, kind: SignalKind },
}

pub enum SignalKind { Approve, Done, Reopen, Cancel }

pub struct Author { pub address: String, pub verified: Verification }
pub enum Verification { None, Dkim, SecretAddress, Both, Platform }
```

- A connector may implement one trait or both. GitHub issues implement both, email only `Inbound`, and a Projects board only `Outbound`. One task can be linked to several items: the email thread it came from, its board card, its PR.
- Connectors report facts: who sent it, how that was verified, and what it says. **Core policy decides** whether it becomes a task. No connector can approve anything by itself.

### Tasks and attempts

- A **task** is the unit people talk about. An **attempt** is one signed manifest that runners execute. A task has one or more attempts.
- Attempt *n+1* is created from a refinement. Its prompt carries the original request, every refinement so far, and the previous attempt's output. Its input bundle is the task branch as it stands, so the agent continues from its own previous work instead of starting over.
- Lifecycle: `Draft → Queued → Running(n) → AwaitingFeedback(n) → Queued (refinement) | Done | Cancelled`.
- **One branch and one PR per task** (`toto/<task>`). Each attempt adds a commit to it. Today it is one PR per result. With redundancy (ADR 6), the first verified result for an attempt is used; the others are recorded on the issue.
- "Done" is an explicit signal: a merged PR, a closed issue, a `/done` comment, or a "done" reply. Silence is not done; after a configurable idle period the task is closed as stale.

### Approval

- A new task or a refinement becomes an attempt only if the policy approves it. Approval comes either from a **pre-approved sender** within their limits, or from an `Approve` signal by a maintainer.
- Pre-approved email senders are listed in the project's intake config, each with a verification requirement (`dkim`, `secret-address` or `both`) and limits: allowed kinds, maximum cost estimate, tasks per day, and an undo window before the task is queued.
- DKIM is read from the receiving provider's `Authentication-Results` header for the configured inbox (`dkim=pass` with a `header.d` aligned to the sender's domain). toto does not verify DKIM signatures itself in v1. The secret address is a plus-address (`toto+<secret>@…`) known only to that sender.
- Automated mail (`Auto-Submitted` other than `no`, `Precedence: bulk|list|junk`, and mail from the inbox's own address) is ignored and never answered, so two robots cannot loop.
- Refinements that arrive while an attempt is running are batched into the next attempt. A task has an attempt cap (default 5); beyond it, a maintainer must approve each further attempt.
- The kind of a task comes from a subject tag (`[docs]`), or else the sender's default kind. Its cost estimate is the default for that kind unless the request says otherwise; the policy limits apply to the estimate.

### Where it runs

`toto project sync` is one pass of: receive from every inbound, apply policy, sign and post attempts, turn verified results into commits on the task branch and PR, and publish every changed task to every outbound. It replaces `results-to-pr` (which stays as an alias) and runs as the project's scheduled job. Task state lives in the project's queue repository as a JSON file per task (`.toto/tasks/<id>.json`), committed by the job. No new server and no database are needed.

## Consequences

- People can ask for work by email, and feedback flows back as refinements, without contributors' runners changing at all. Every attempt is still a manifest signed with the project's key.
- The manifest gains optional `task` and `attempt` fields, inside the signed payload, so a result can be tied to its task and attempt without trusting an issue body. Old runners ignore unknown fields. Old manifests without the fields are tasks with one attempt.
- Each pre-approved sender is a credential: whoever controls that mailbox, or learns the secret address, can spend contributors' donated tokens on this project within the sender's limits. The limits and the undo window bound that damage, and the project owner guide must say so plainly.
- The prompt of a refinement attempt contains text from people other than maintainers. That text was already possible through `post-task`; now it arrives faster. It is shown in fences, it is never executable configuration, and the agent's sandbox is unchanged.
- Board connectors only display state, so a board that is wrong or is edited by hand cannot cause work to run. Moving a card can at most send a `Signal`, which goes through the same policy.

## Open questions

- The exact `TaskView` shape that every board can show (title, state, attempt, tokens used, links). It will be settled with the first two outbound connectors, not before.
- Whether a task's state file should live on a dedicated `toto-state` branch so the job never writes to the default branch.
- Replying to email: confirmations and "result ready" mails need an SMTP sender, which needs its own credential and its own anti-loop rules. Deferred until after the first email intake works.
