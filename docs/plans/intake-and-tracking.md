# Plan: task intake, refinement and tracking

Decision record: [ADR 16](../adr/0016-task-intake-refinement-and-tracking.md). This page is the order of work. Each phase ends with something usable, tests, docs and a push.

Everything here runs on the **project side** (`toto project sync`). Contributors' runners change only in Phase 1, where they learn to ignore two new optional manifest fields.

## Phase 0: the core model (no connectors yet)

The goal is tasks and attempts as data, with the policy that approves them, tested with in-memory connectors.

- `src/intake/mod.rs`: the `Inbound` and `Outbound` traits, `Received`, `Author`, `Verification`, `SignalKind`, `ItemRef`, `ReceivedRef`, `TaskView`.
- `src/intake/task.rs`:
  - `Task { id, project_id, kind, title, state, attempts: Vec<Attempt>, conversation: Vec<Turn>, links: Vec<ItemRef>, branch, pr, created, updated }`.
  - `Turn` covers a request, a refinement or a result summary, each with its author.
  - State transitions are a pure function, `Task::apply(event) -> Result<Vec<Effect>>`. Effects include `PostAttempt`, `Publish` and `Close`. Exhaustive unit tests cover the lifecycle `Draft → Queued → Running → AwaitingFeedback → Queued | Done | Cancelled`, including refinements batched while running and the attempt cap.
- `src/intake/policy.rs`:
  - `IntakePolicy { senders: Vec<Sender>, maintainers: Vec<String>, kinds: HashMap<kind, KindDefaults>, attempt_cap, stale_days }`.
  - `decide(&Received, &Task?) -> Decision::{Accept, Hold(reason), Ignore(reason)}`.
  - Per-sender daily counts and the undo window (a held task is queued after N minutes unless cancelled).
- `src/intake/store.rs`: a JSON file per task under a directory, written atomically, the same way the config file is saved. A sync is idempotent: running it twice on the same input changes nothing.
- Fake `MemInbound`/`MemOutbound` for tests.

## Phase 1: attempts as signed manifests, one PR per task

- `TaskManifest` gains `#[serde(default, skip_serializing_if = "Option::is_none")] task: Option<String>` and `attempt: Option<u32>`, both inside the signed payload. Add a test that an old runner's manifest without them still verifies and runs, and that the runner's echo of the manifest keeps them.
- Attempt prompt builder: the original request, the refinements in order, and the previous attempt's output, each fenced, under the project's standing prompt from `.toto/agent`. Cap the conversation length; trim the oldest result summaries first, never the requests.
- Input bundle for attempt *n+1*: a tar of the task branch at its head, via the same uploader as `post-task`.
- `pr_flow`:
  - The branch becomes `toto/<task>`, falling back to the manifest id for manifests without a task.
  - The first verified result for an attempt is committed onto the branch. If the branch has no PR yet, open one; otherwise push and comment "attempt n".
  - Later redundant results for the same attempt are recorded on the issue and not applied.
  - Keep the protected-path and `max_open` checks.
- A merged PR emits `Done`. A closed, unmerged PR emits `Cancel`.
- Tests: two attempts land on one branch as two commits in one PR, using the existing fake GitHub server in `tests.rs`.

## Phase 2: `toto project sync` and GitHub as the first connector

- `toto project sync --config project.toml` runs one pass: receive, decide, apply, sign and post, collect results, publish, and save the state. `results-to-pr` becomes an alias for a sync with no inbounds or outbounds configured.
- The project's intake config (`.toto/intake.toml` in the project repository, read at the default branch) holds the senders, kinds, the attempt cap and the connectors.
- GitHub `Inbound`:
  - An issue form (`.github/ISSUE_TEMPLATE/toto-task.yml`) labelled `toto:request`. A new issue with that label is a `Message` with no thread.
  - Comments on a request issue or on the task's PR are refinements.
  - `/approve`, `/done`, `/reopen` and `/cancel` are `Signal`s.
  - Authors are verified by the platform (`Verification::Platform`). Whether an author is a maintainer comes from the repository's collaborator permission, not from the comment text.
  - Comments by toto itself and by bots are ignored.
- GitHub `Outbound` (issues): the request issue carries a status comment that is edited in place (state, attempt, tokens, PR link), so there is never a stream of comments.
- An example workflow in `docs/examples/project/.github/workflows/toto-sync.yml` runs on a schedule and on `issue_comment` and `issues` events.
- Tests:
  - An end-to-end test against the fake GitHub covering issue form → approval → attempt 1 → PR → comment → attempt 2 → same PR → `/done` → closed.
  - Bot comments are ignored.
  - A non-maintainer cannot `/approve`.

## Phase 3: GitHub Projects (v2) outbound

- A GraphQL client (ureq plus hand-written queries; no new SDK dependency).
- `publish` adds the request issue to the project, and sets a single-select Status field (`Queued`, `Running`, `Awaiting feedback`, `Done`) and number fields (attempt, tokens).
- Field and option ids are looked up once per sync and cached in the state directory. A missing field gives a clear error naming the field to create.
- Moving a card is not read back in v1. The board only displays state.
- Tests: a fake GraphQL endpoint that records the mutations. Publishing the same view twice is a no-op.

## Phase 4: email inbound

- IMAP over TLS with an app password from a secret file, reading one folder. Gmail and Fastmail are documented. Mail that has been handled is moved to a `toto/handled` folder; that move is `acknowledge`.
- Parsing (the `mail-parser` crate):
  - The plain-text part only. Quoted replies are stripped (lines starting with `>` and everything below an "On … wrote:" line).
  - Attachments are ignored in v1.
  - The subject tag `[kind]` sets the kind.
- Threading: `In-Reply-To` and `References` are matched against the Message-IDs stored on the task. A reply is a refinement. A reply whose first line is `done` is a `Done` signal.
- Verification:
  - `Authentication-Results` from the configured inbox's own provider only (`authserv-id` must match the config, since earlier hops' headers can be forged). DKIM must pass, with `header.d` aligned to the sender's domain.
  - The secret plus-address is compared in constant time. The secret is stored hashed in the intake config.
- Loop safety: ignore `Auto-Submitted`, `Precedence: bulk|list|junk`, mail from the inbox's own address, and anything with a `List-Id`.
- Tests: fixture `.eml` files (DKIM pass, fail, misaligned, forged earlier-hop header, auto-reply, quoted reply, secret address) fed through the parser and the policy. Plus a local IMAP test server if one is available in CI; otherwise the IMAP layer stays a thin, separately tested adapter.

## Phase 5: Azure DevOps and the rest (later)

- Azure DevOps Boards `Outbound` (a work item per task, state mapped to the board's states). Its comments can be an `Inbound` with the same commands.
- Replying by email (SMTP): confirmations and "result ready" notices, with `Auto-Submitted: auto-replied` set on every outgoing mail.
- Reading a board's card moves back as `Signal`s.

## Cross-cutting

- **Docs:**
  - `docs/project-owner-guide.md` gets an "Accepting requests" section, with the sender risk stated plainly.
  - `docs/github-queue.md` explains one PR per task.
  - A new `docs/intake.md` covers the config reference and each connector.
  - ADR 16 moves to Accepted after Phase 2 ships.
- **Audit:** every decision (accept, hold, ignore, with its reason) is appended to the project's sync log, so a maintainer can see why a mail did nothing.
- **Limits:** a project-wide daily cap on attempts created, in addition to the per-sender limits. Contributors' own caps are unchanged and still apply.

## Order and size

| Phase | Depends on | Rough size |
|---|---|---|
| 0 core model | none | medium |
| 1 attempts + one PR per task | 0 | medium |
| 2 sync + GitHub in/out | 0, 1 | large |
| 3 Projects v2 | 2 | small |
| 4 email | 2 | medium |
| 5 Azure DevOps, SMTP | 2 | later |

Phases 0 to 2 make the first useful slice: request by issue form, refine by comment, one PR that grows. Phases 3 and 4 are independent of each other once Phase 2 is in.
