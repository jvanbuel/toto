# Task intake, refinement and tracking

`toto project sync` is the project side of toto in one command. It runs in the project's own scheduled workflow, with the project's signing key, and in each pass it:

1. turns verified results into commits on each task's branch and its one pull request;
2. reads what arrived: requests from an issue form or by email, comments, and commands;
3. decides, by the policy in `.toto/intake.toml`, what becomes work;
4. posts the attempts that are due as signed task manifests, for contributors' runners to pick up;
5. shows every task where people look: a status comment on its request issue, a card on a Projects board;
6. commits its state to the `toto-state` branch.

Contributors' runners are unchanged: they still see nothing but signed manifests. Decision record: [ADR 16](adr/0016-task-intake-refinement-and-tracking.md).

## Setting it up

1. Copy `docs/examples/project/.toto/intake.toml` into your repository and edit it (reference below).
2. Copy `docs/examples/project/.github/ISSUE_TEMPLATE/toto-task.yml` and create the `toto:request` label (GitHub only applies labels that exist). Match the form's kinds to your config.
3. Copy `docs/examples/project/.github/workflows/toto-sync.yml`. It replaces `toto-results.yml`; remove that one.
4. Add the repository secret `TOTO_PROJECT_KEY`: the hex seed in the file `toto project-key` wrote. Optionally add `TOTO_TOKEN` (a fine-grained token, so toto's pull requests run CI), `TOTO_PROJECTS_TOKEN` (for a board) and `TOTO_IMAP_PASSWORD` (for email).

## How a task goes

```
Draft ──approve──▶ Queued ──posted──▶ Running(n) ──result──▶ AwaitingFeedback(n) ──comment──▶ Queued …
                                                                     │
                                                         /done, merge ▼ /cancel, close
                                                                   Done   Cancelled
```

- **A request** is an issue opened with the form, or a mail to the inbox. A maintainer's request (write access to the repository) or a pre-approved sender's (within their limits) is queued at once. Anyone else's waits, visibly, in `Draft` ("Awaiting approval") until a maintainer comments `/approve`. Mail from unknown or unverified senders is dropped; the sync log says so.
- **An attempt** is one signed manifest, `<task>-a<n>`, posted as a task issue for runners. Attempt 1 starts from the base branch. Each later attempt starts from the task's branch, so the agent continues from its own work, and its prompt carries the original request, every refinement and what earlier attempts reported. Attempts are posted with `redundancy: 1`.
- **One branch and one pull request per task**, `toto/<task>`. Each attempt adds a commit (with a `Toto-Attempt:` trailer). The first one opens the pull request, with `Closes #<request>`; later ones push to it and comment.
- **A comment is a refinement.** Any comment on the request issue or the pull request (other than a command) is part of the task's conversation, approved by the same rules as a request. Comments that arrive while an attempt runs are batched into the next one. A comment on a finished task reopens it.
- **Done is said, not assumed.** Merging the pull request, closing the request issue, `/done`, or replying "done" by mail ends a task. Closing the pull request unmerged, `/cancel`, or "cancel" by mail cancels it, and toto closes the pull request. A task with no activity for `stale_days` is closed.
- **Commands** (first line of a comment): `/approve` (maintainers: run what waits, and allow one attempt past the cap), `/done`, `/cancel`, `/reopen` (maintainers, or whoever asked). `/approve` approves **everything** waiting on the task, including comments from people who are not maintainers, and their text goes into the next attempt's prompt: read them first. While a comment waits for approval, the task waits too, even for a maintainer's later refinement.
- **Caps**: `attempt_cap` attempts per task, then each further one needs `/approve`; `daily_attempt_cap` attempts per day across the project; each sender's `per_day`; `max_open` pull requests. Contributors' own caps apply on top.

On GitHub a task is three kinds of object: the **request issue** (what was asked; its status comment links everything), one **task issue per attempt** (the signed manifest that runners claim and answer), and the **pull request**. Requests that came by mail get a request issue too (a mirror), so maintainers can see, discuss and approve them.

## `.toto/intake.toml`

| Key | Default | Meaning |
|---|---|---|
| `project_id` | required | The id runners know your key by (`customizations.toto.id`). |
| `repo` | required | `owner/name` of the repository whose issues are the queue. |
| `base` | `main` | Branch attempts start from and pull requests target. |
| `state_branch` | `toto-state` | Where the sync keeps its state. Never the base branch. |
| `attempt_cap` | 5 | Attempts per task before each further one needs `/approve`. |
| `daily_attempt_cap` | 20 | Attempts posted per UTC day across the project. |
| `stale_days` | 14 | Idle tasks are closed after this long. |
| `max_open` | 10 | No new toto pull requests while this many are open (attempts on open ones still land). |
| `protect` | `[]` | Extra paths a result may not touch, on top of `.github/`, `.git/`, CI files, `CODEOWNERS`. |
| `max_input_bytes` | 64 MiB | Largest input bundle (a checkout of the branch). |
| `max_prompt_chars` | 48000 | Longer conversations drop the oldest results first, never a request. |
| `default_kind` | first kind | The kind of a request that names none. |
| `[kinds.<name>]` | at least one | `estimate` (tokens, required), `tool_requirements` (`["omnigent"]`), `sandbox_profile`, `format` (`text`), `max_output_bytes` (32 KiB), `max_artifact_bytes` (4 MiB). |
| `[[senders]]` | none | Pre-approved senders, below. |
| `[github]` | on | `requests` (read the issue form and comments), `status` (status comments and mirrors), `label` (`toto:request`). |
| `[email]` | off | The inbox, below. |
| `[projects_v2]` | off | A board, below. |

A request's kind is a `[kind]` tag at the start of its title or subject, or the form's **Kind** field (or a `Kind:` line), else the sender's `default_kind`, else the project's. Its estimate is the form's **Estimate** field (or an `Estimate:` line), else the kind's. A kind that is not configured holds the request for a maintainer.

### Pre-approved senders

```toml
[[senders]]
address = "github:alice"      # a GitHub account, or a mail address in lower case
verify = "platform"           # github: platform; mail: dkim (default), secret-address or both
kinds = ["docs"]              # empty: every kind
default_kind = "docs"
max_estimate = 40000          # default: the kind's estimate
per_day = 3                   # requests and refinements accepted per UTC day
secret_sha256 = "…"           # for secret-address and both
```

**Each sender is a credential.** Whoever controls that GitHub account or mailbox, or learns the secret address, can spend contributors' donated tokens on your project, up to that sender's limits. Keep the list short and the limits tight. A sender over a limit is not dropped: the request waits for a maintainer's `/approve`.

## Email

```toml
[email]
address = "toto@acme.example"     # the inbox people write to
imap_host = "imap.gmail.com"
imap_port = 993
user = "toto@acme.example"        # default: address
password_env = "TOTO_IMAP_PASSWORD"
folder = "INBOX"
authserv_id = "mx.google.com"     # whose Authentication-Results to believe
max_per_pass = 50
```

The sync reads new mail over IMAP (TLS), from the highest UID it handled; it never marks, moves or deletes mail. It believes only what your inbox's provider recorded:

- **DKIM**: the topmost `Authentication-Results` header whose id is `authserv_id` must say `dkim=pass` for a domain aligned with the From address (the same domain, or a subdomain either way). toto does not check signatures itself. Headers further down are ignored, because a sender can write their own. For Gmail the id is `mx.google.com`; for another provider, it is the first word of the topmost `Authentication-Results` header in a mail your inbox received.
- **Secret address**: `toto project secret-address toto@acme.example` prints an address like `toto+<32 random characters>@acme.example` for the sender, and the `secret_sha256` for their entry. The config holds only the hash. Tags shorter than 32 characters are ignored.
- **Addressed**: the inbox must be in `To` or `Cc`, so a forwarded mail that still passes DKIM does not count.

Mail with `Auto-Submitted` (other than `no`), `Precedence: bulk|list|junk` or a `List-Id`, and mail from the inbox itself, is skipped and never answered. Replies are matched to their task by `In-Reply-To` and `References`; quoted text and signatures are stripped. A reply whose first line is `done`, `cancel` or `reopen` is that command. toto sends no mail in this version: a sender follows the task on its mirrored issue.

## A GitHub Projects board

```toml
[projects_v2]
owner = "acme"                    # organisation, or a user with owner_is_user = true
number = 3                        # from the board's URL
token_env = "TOTO_PROJECTS_TOKEN"
status_field = "Status"
attempt_field = "Attempt"         # optional number fields
tokens_field = "Tokens"
```

**Projects (v2) is not reachable with the workflow's own `GITHUB_TOKEN`.** Create a fine-grained token, or use a GitHub App, with the `project` scope, and store it as `TOTO_PROJECTS_TOKEN`.

Each task's request issue becomes a card. Its Status is set from the task's state, using the first option the board has: Draft is `Awaiting approval`, `Queued` or `Todo`; Queued is `Queued` or `Todo`; Running is `Running` or `In Progress`; AwaitingFeedback is `Awaiting feedback`, `In Review` or `In Progress`; Done is `Done`; Cancelled is `Cancelled` or `Done`. GitHub's default board works as it is. A missing field or option is an error naming it; it does not hold up the rest of the pass. The board only displays state: moving a card does nothing.

## The state branch

The workflow runs on a fresh machine each time, so the sync keeps everything on `toto-state`:

- `tasks/<id>.json`: each task, its conversation, attempts and links;
- `cursors/<connector>.json`: where each inbound left off;
- `senders/<address>.json`: today's count per sender;
- `cache/<connector>.json`: ids a board looked up;
- `log/<date>.jsonl`: every decision and why (accept, hold, ignore, post, result, signal, cap, error).

The branch is written with git plumbing, one commit per pass, and the default branch is never touched. If another pass pushed first, this pass stops and the next one redoes its work. That is safe because every step is idempotent: attempt ids are deterministic and looked up before posting, an attempt already on its branch is not applied again, and a received item already handled is skipped. The workflow's `concurrency` group makes such races rare in the first place.

To see why a mail or comment did nothing, read that day's log on the `toto-state` branch.
