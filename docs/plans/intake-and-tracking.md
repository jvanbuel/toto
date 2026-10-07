# Plan: task intake, refinement and tracking

Decision record: [ADR 16](../adr/0016-task-intake-refinement-and-tracking.md). This page is the order of work. Each phase ends with something usable, tests, docs and a push.

**Status (2026-10-07): Phases 0 to 4 are implemented** (`src/intake/`, tests in `src/intake/tests.rs`, user documentation in [docs/intake.md](../intake.md)). Phase 5 is still later. ADR 16's "As built" section lists where the code differs from this plan.

Everything here runs on the **project side** (`toto project sync`), as a scheduled job on a fresh machine each time. That shapes the whole design: the job keeps no local state, every step is idempotent, and two passes running at once must not do anything twice. Contributors' runners change only in Phase 1, where they learn to ignore two new optional manifest fields.

## Phase 0: the core model (no connectors yet)

The goal is tasks and attempts as data, with the policy that approves them, tested with in-memory connectors.

- `src/intake/mod.rs`: the `Inbound` and `Outbound` traits, `Received`, `Author`, `Verification`, `SignalKind`, `ItemRef`, `ThreadRef`, `Cursor`, `TaskView`.
  - `Inbound::receive(&self, since: &Cursor) -> (Vec<Received>, Cursor)`. The cursor is opaque to core and stored with the task state, so a connector holds nothing between passes. There is no `acknowledge`: a comment cannot be marked taken, and moving mail is fragile.
  - A `Message` carries the raw `ThreadRef` the connector saw. Core resolves it against the link table: resolved means a refinement, unresolved or absent means a new task. Connectors never decide this.
- `src/intake/task.rs`:
  - `Task { id, project_id, kind, title, state, attempts: Vec<Attempt>, conversation: Vec<Turn>, links: Vec<ItemRef>, branch, pr, tokens_used, created, updated }`. `tokens_used` is the sum of `tokens_used` over the accepted results.
  - `Turn` covers a request, a refinement or a result summary, each with its author.
  - State transitions are a pure function, `Task::apply(event) -> Result<Vec<Effect>>`. Effects include `PostAttempt`, `Publish` and `Close`. Exhaustive unit tests cover the lifecycle `Draft → Queued → Running → AwaitingFeedback → Queued | Done | Cancelled`, including refinements batched while running and the attempt cap. A stale task (idle longer than `stale_days`) is closed through the same function with a `Stale` event, so it gets the same audit line as everything else.
  - Attempt ids are deterministic: `<task>-a<n>`.
- `src/intake/policy.rs`:
  - `IntakePolicy { senders: Vec<Sender>, maintainers: Vec<String>, kinds: HashMap<kind, KindDefaults>, attempt_cap, daily_attempt_cap, stale_days }`.
  - `decide(&Received, Option<&Task>, &SenderUsage) -> Decision::{Accept, Hold(reason), Ignore(reason)}`. No undo window (ADR 16).
- `src/intake/store.rs`: the state branch. `Store::open(repo_dir, "toto-state")` checks the branch out into a worktree; `load`/`save` read and write `tasks/<id>.json`, `senders/<address>.json` (daily counts), `cursors/<connector>.json` and `cache/`; `commit_and_push` makes one commit per pass. A non-fast-forward push means another pass won: the store returns `Error::Concurrent` and the pass stops without posting anything further. Tests run against a local bare repository.
- Fake `MemInbound`/`MemOutbound` for tests.

## Phase 1: attempts as signed manifests, one PR per task

- `TaskManifest` gains `#[serde(default, skip_serializing_if = "Option::is_none")] task: Option<String>` and `attempt: Option<u32>`, both inside the signed payload. Add a test that an old runner's manifest without them still verifies and runs, and that the runner's echo of the manifest keeps them.
- Attempt prompt builder: the original request, the refinements in order, and the previous attempt's output, each fenced, under the project's standing prompt from `.toto/agent`. Cap the conversation length; trim the oldest result summaries first, never the requests.
- Input bundle: every attempt is a tar of a real checkout, uploaded the way `post-task` does. Attempt 1 is the base branch at its head; attempt *n+1* is the task branch at its head. One code path, and `inputs` is always the hash of a checkout.
- Attempts are posted with `redundancy: 1`. `pr_flow` ignores the field today, so a higher value would pay for a comparison nobody makes; revisit when ADR 6 is implemented.
- `pr_flow`:
  - The branch becomes `toto/<task>`, falling back to the manifest id for manifests without a task.
  - The first verified result for an attempt is committed onto the branch. If the branch has no PR yet, open one with `Closes #<request>` in the body; otherwise push and comment "attempt n".
  - A later result for the same attempt is recorded on the task issue and not applied.
  - Keep the protected-path and `max_open` checks.
- A merged PR emits `Done`. A closed, unmerged PR emits `Cancel`.
- Tests: two attempts land on one branch as two commits in one PR, using the existing fake GitHub server in `tests.rs`.

## Phase 2: `toto project sync` and GitHub as the first connector

- `toto project sync --config project.toml` runs one pass: open the state branch, receive, decide, apply, sign and post, collect results, publish, save, commit and push. `results-to-pr` becomes an alias for a sync with no inbounds or outbounds configured.
- The project's intake config (`.toto/intake.toml` in the project repository, read at the default branch) holds the senders, kinds, the caps and the connectors.
- On GitHub a task is three objects: the **request issue** (the form, labelled `toto:request`), one **task issue per attempt** (the signed manifest, `toto:task`, as today) and the **PR**. The request issue's status comment links all of them.
- GitHub `Inbound`:
  - A new issue with the `toto:request` label (from `.github/ISSUE_TEMPLATE/toto-task.yml`) is a `Message` with no thread.
  - Comments on a request issue or on the task's PR are `Message`s whose thread is the issue or PR number.
  - `/approve`, `/done`, `/reopen` and `/cancel` are `Signal`s.
  - The cursor is the highest comment id seen per issue.
  - Authors are verified by the platform (`Verification::Platform`). Whether an author is a maintainer comes from the repository's collaborator permission, not from the comment text.
  - Comments by toto itself and by bots are ignored.
- GitHub `Outbound` (issues): the request issue carries one status comment that is edited in place (state, attempt, tokens, links), so there is never a stream of comments.
- The example workflow in `docs/examples/project/.github/workflows/toto-sync.yml` runs on a schedule and on `issues` and `issue_comment` events, with `concurrency: { group: toto-sync, cancel-in-progress: false }` so passes queue instead of overlapping. The state branch push is the second guard, for a pass started outside Actions.
- Tests:
  - An end-to-end test against the fake GitHub covering issue form → approval → attempt 1 → PR → comment → attempt 2 → same PR → `/done` → closed.
  - Two passes over the same input produce one attempt (the second finds `<task>-a1` posted).
  - Bot comments are ignored.
  - A non-maintainer cannot `/approve`.

## Phase 3: GitHub Projects (v2) outbound

- Projects v2 is not reachable with the workflow's default `GITHUB_TOKEN`: the project owner needs a fine-grained PAT or a GitHub App with the `project` scope, stored as a secret. The guide says so before anything else in this section.
- A GraphQL client (ureq plus hand-written queries; no new SDK dependency).
- `publish` adds the request issue to the project, and sets a single-select Status field (`Queued`, `Running`, `Awaiting feedback`, `Done`) and number fields (attempt, tokens).
- Field and option ids are looked up once per pass and cached under `cache/` on the state branch. A missing field gives a clear error naming the field to create.
- Moving a card is not read back in v1. The board only displays state.
- Tests: a fake GraphQL endpoint that records the mutations. Publishing the same view twice is a no-op.

## Phase 4: email inbound

- IMAP over TLS with an app password from a secret file, reading one folder. Gmail and Fastmail are documented. The cursor is the highest IMAP UID seen; handled mail is not moved.
- Parsing (the `mail-parser` crate):
  - The plain-text part only. Quoted replies are stripped (lines starting with `>` and everything below an "On … wrote:" line).
  - Attachments are ignored in v1.
  - The subject tag `[kind]` sets the kind.
- Threading: the connector reports `In-Reply-To` and `References` as the thread; core matches them against the Message-IDs stored on the task's links. A reply whose first line is `done` is a `Done` signal.
- Verification:
  - `Authentication-Results` from the configured inbox's own provider only (`authserv-id` must match the config, since earlier hops' headers can be forged). DKIM must pass, with `header.d` aligned to the sender's domain, and the inbox must appear in `To` or `Cc`.
  - The secret plus-address is checked by hashing the local part and comparing with the hash in the intake config; the secret must be at least 128 bits, since the config is public.
- Loop safety: ignore `Auto-Submitted` other than `no`, `Precedence: bulk|list|junk`, mail from the inbox's own address, and anything with a `List-Id`.
- Tests: fixture `.eml` files (DKIM pass, fail, misaligned, forged earlier-hop header, auto-reply, quoted reply, secret address, inbox not addressed) fed through the parser and the policy. The IMAP layer sits behind an `ImapSource` trait with a fake in tests; no IMAP server in CI.

## Phase 5: Azure DevOps and the rest (later)

- Azure DevOps Boards `Outbound` (a work item per task, state mapped to the board's states). Its comments can be an `Inbound` with the same commands.
- Replying by email (SMTP): confirmations and "result ready" notices, with `Auto-Submitted: auto-replied` set on every outgoing mail. An undo window for pre-approved senders only makes sense once this exists.
- Reading a board's card moves back as `Signal`s.

## Cross-cutting

- **Docs:**
  - `docs/project-owner-guide.md` gets an "Accepting requests" section, with the sender risk stated plainly and the state branch explained.
  - `docs/github-queue.md` explains one PR per task and the three objects.
  - A new `docs/intake.md` covers the config reference and each connector.
  - ADR 16 moves to Accepted after Phase 2 ships.
- **Audit:** every decision (accept, hold, ignore, with its reason) is appended to `log/<date>.jsonl` on the state branch, so a maintainer can see why a mail did nothing.
- **Limits:** `daily_attempt_cap` across the project, in addition to the per-sender limits. Contributors' own caps are unchanged and still apply.

## Order and size

| Phase | Depends on | Rough size |
|---|---|---|
| 0 core model and state branch | none | medium |
| 1 attempts + one PR per task | 0 | medium |
| 2 sync + GitHub in/out | 0, 1 | large |
| 3 Projects v2 | 2 | small |
| 4 email | 2 | medium |
| 5 Azure DevOps, SMTP | 2 | later |

Phases 0 to 2 make the first useful slice: request by issue form, refine by comment, one PR that grows. Phases 3 and 4 are independent of each other once Phase 2 is in.
