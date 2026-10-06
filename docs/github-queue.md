# GitHub issues as the queue

The first queue for toto (ADR 1's "simpler v1 option"): no server to run. A project posts tasks as issues in its own repository; contributors' runners claim and answer them with comments. Implemented in `src/github_queue.rs`; set it up with a `queues` entry of kind `github` in the runner config.

```json
"queues": [{"kind": "github", "repo": "org/project", "token_file": "/home/me/.config/toto/gh.token"}]
```

## What lives where

| Thing | GitHub object | Who writes it |
|---|---|---|
| Task | An open issue labelled `toto`. The body starts with `<!-- toto:task -->` and holds the signed envelope in a ```` ```json ```` block. | The project |
| Input bundle | A release asset named by its SHA-256 on the pre-release tagged `toto-bundles` | The project |
| Lease | A *claim comment*: `<!-- toto:claim runner=<id> lease=<secs> released=0\|1 beat=<n> -->` | The runner |
| Heartbeat, release | An **edit** of the runner's own claim comment (`released=1` ends the lease at once) | The runner |
| Result | One or more *result comments*: `<!-- toto:result runner=<id> sum=<12 hex> part=i/n -->` plus a ```` ```json ```` block holding the signed result, split at 60,000 bytes, at most 8 parts | The runner |

A runner needs only to **comment on issues**, which any GitHub user can do on a public repository, so a contributor's token can be a fine-grained token with the least access that allows that (or a classic `public_repo` token). Reading needs no token, but anonymous requests have a very low rate limit. A project needs to create issues and labels and to upload release assets.

## Who holds a lease

Decided from GitHub's own comment order and timestamps, never from a runner's clock. Replay the claim comments in order: a claim wins if nobody holds the lease at the moment it was created, or its author already holds it. A lease ends `lease` seconds after the claim comment's last edit; a release ends it at once. A runner claims by posting its comment, then re-reading: if its comment is not the winner it backs off. Leases are capped at six hours. "Now" is GitHub's `Date` header.

A task is offered when it is open, has no lease and has no complete, correctly signed result for that task id. Polls revalidate with ETags, so an unchanged queue costs no rate limit.

## Limits

- **Result size.** A result (output plus artifacts, base64) must fit 8 comments, about 480 KB; submit fails with a clear message otherwise. Projects set `max_artifact_bytes` accordingly.
- **Latency and rate.** A runner polls issues, then the comments of each issue that has any. Fine for a pilot with a modest number of open tasks; a busy queue wants a coordinator (`docs/queue-protocol.md`).
- **Redundancy.** The first complete result closes the task for everyone; `redundancy > 1` is not honoured by this queue.

## Trust

GitHub is not a trust anchor, same as every queue (ADR 8): runners verify the project's signature on a task, and projects verify the runner's signature on a result (`toto github-results` and `toto extract-result` do). A stranger who can comment can still be annoying:

- a fake claim holds a task for at most six hours;
- a result signed with the stranger's own key and carrying the right task id hides the task from other runners, until the project deletes that comment (the project sees every result, so it can tell).

So this queue suits pilots and communities where the project can moderate. For an open crowd, use a coordinator that authenticates runners.

## Results become pull requests, automatically

Contributors only offer tokens; they never see the project or its repository. The project side is automated: `toto results-to-pr` (run on a schedule by a GitHub Action, `docs/examples/toto-results.yml`) handles every task issue that has a result:

- **File changes** become a branch `toto/<task>-<runner>` and a pull request on the default branch. The PR body carries the provenance (runner id, tokens used, output and artifact hashes) and the model's output inside a code fence that the output cannot close. Maintainers review and merge it like any contribution, with their usual CI, CODEOWNERS and approvals. The task issue gets a comment linking the PR and is closed.
- **Text-only results** (no files) are posted as a comment on the task issue, which is then closed.
- **A result that changes nothing** is noted on the issue and the issue is closed.

Safeguards, because the content is model output:

- Only tasks whose signature verifies against a key you pass with `--project id=<hex>` are acted on, and the runner's signature and both hashes are checked again.
- Paths are validated; symlinks are never followed or written through; only the executable bit of a file mode is kept.
- A result that touches `.github/`, `.gitlab-ci.yml`, `.git/`, `CODEOWNERS`, `.gitmodules` or `.githooks/` (case-insensitive, extend with `--protect`) is **not** applied: it is noted on its issue and left open for a maintainer. A model must not be able to add a CI workflow.
- `--max-open N` (default 10) stops opening PRs while N toto PRs are open, so a flooded queue cannot flood the repository; the rest wait for the next run.
- The checkout must be clean, and `git add` only stages the paths the result touched.
- Everything is idempotent (a marker comment on the issue, a branch per result). A failure of the network or `git push` aborts the run and the next run retries; only a bad *result* is refused and recorded.

Pushes made with the Action's default `GITHUB_TOKEN` do not trigger other workflows, so give the workflow a fine-grained token or a GitHub App token (`TOTO_TOKEN`) if the PRs should get CI.

## Project side

```
toto post-task --key project.key --config cfg.json --github org/project --github-token-file gh.token task.json [--bundle dir]
toto results-to-pr org/project --project id=<hex pubkey> --base main      # PRs for finished tasks (normally on a schedule)
toto github-results org/project --out results/      # verified results, one file each
toto extract-result results/<id>.<runner>.json out/
```
