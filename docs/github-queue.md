# GitHub issues as the queue

The first queue for toto (ADR 1's "simpler v1 option"): no server to run. A project posts tasks as issues in its own repository; contributors' runners claim and answer them with comments. Implemented in `src/github_queue.rs`; set it up with a `queues` entry of kind `github` in the runner config.

```json
"queues": [{"kind": "github", "repo": "org/project", "token_file": "/home/me/.config/toto/gh.token"}]
```

## What lives where

| Thing | GitHub object | Who writes it |
|---|---|---|
| Task | An open issue labelled `toto`. The body starts with `<!-- toto:task -->` and holds the signed envelope in a ```` ```json ```` block. | The project |
| Input bundle, context bundle | A release asset named by its SHA-256 on the pre-release tagged `toto-bundles` | The project |
| Lease | A *claim comment*: `<!-- toto:claim runner=<id> lease=<secs> released=0\|1 beat=<n> -->` | The runner |
| Heartbeat, release | An **edit** of the runner's own claim comment (`released=1` ends the lease at once) | The runner |
| Result | One or more *result comments*: `<!-- toto:result runner=<id> sum=<12 hex> part=i/n -->` plus a ```` ```json ```` block holding the signed result, split at 60,000 bytes, at most 8 parts | The runner |

A runner needs only to **comment on issues**, which any GitHub user can do on a public repository, so a contributor's token can be a fine-grained token with the least access that allows that (or a classic `public_repo` token). Reading needs no token, but anonymous requests have a very low rate limit. A project needs to create issues and labels and to upload release assets.

## Who holds a lease

Decided from GitHub's own comment order and timestamps, never from a runner's clock. Replay the claim comments in order: a claim wins if nobody holds the lease at the moment it was created, or its author already holds it. A lease ends `lease` seconds after the claim comment's last edit; a release ends it at once. A runner claims by posting its comment, then re-reading: if its comment is not the winner it backs off. Leases are capped at six hours. "Now" is GitHub's `Date` header.

A task is offered when it is open, has no lease and has no complete, correctly signed result for that task id. Polls revalidate with ETags, so an unchanged queue costs no rate limit.

## Limits

- **Result size.** A result (output plus artifacts, base64) must fit 8 comments, about 480 KB; submit fails with a clear message otherwise. Projects set `max_artifact_bytes` accordingly.
- **Latency and rate.** A runner polls issues, then the comments of each issue that has any. Fine for a pilot with a modest number of open tasks; a busy queue wants the HTTP coordinator (`docs/queue-protocol.md`).
- **Redundancy.** The first complete result closes the task for everyone; `redundancy > 1` is not honoured by this queue.

## Trust

GitHub is not a trust anchor, same as every queue (ADR 8): runners verify the project's signature on a task, and projects verify the runner's signature on a result (`toto github-results` and `toto extract-result` do). A stranger who can comment can still be annoying:

- a fake claim holds a task for at most six hours;
- a result signed with the stranger's own key and carrying the right task id hides the task from other runners, until the project deletes that comment (the project sees every result, so it can tell).

So this queue suits pilots and communities where the project can moderate. For an open crowd, use a coordinator that authenticates runners.

## Project side

```
toto post-task --key project.key --config cfg.json --github org/project --github-token-file gh.token task.json [--bundle dir] [--context dir]
toto github-results org/project --out results/      # verified results, one file each
toto extract-result results/<id>.<runner>.json out/
```
