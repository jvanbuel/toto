# Queue protocol, version 1

The wire protocol between a `toto` runner and a coordinator (ADR 1, ADR 8). The reference implementation is `toto serve-queue` (a spool directory served over HTTP); `HttpQueue` in `src/http_queue.rs` is the client. Any service that implements these routes can replace it.

**The coordinator is not a trust anchor.** The runner checks the project's signature on every task (DSSE, ADR 3), signs its own results, and checks input bundles against the hash in the signed manifest. A coordinator can withhold, delay or reorder work. It cannot forge a task or a result.

All bodies are JSON unless noted. If the server has a token, every request needs `Authorization: Bearer <token>` (401 otherwise). Use https outside a trusted network: `toto doctor` warns about plain http to non-loopback hosts.

| Request | Body | Response |
|---|---|---|
| `GET /v1/tasks` | | 200: array of DSSE envelopes for tasks that are unleased (or whose lease expired) and have no result |
| `POST /v1/tasks/{id}/claim` | `{"runner_id", "lease_secs"}` | 204, or 409 `{"error"}` if another runner holds an unexpired lease |
| `POST /v1/tasks/{id}/heartbeat` | `{"runner_id", "lease_secs"}` | 204 extends the lease, or 409 if the lease was lost |
| `POST /v1/tasks/{id}/release` | `{"runner_id"}` | 204 (no effect if the runner does not hold the lease) |
| `PUT /v1/results` | a signed result (`{"envelope", "artifacts"}`) | 204; idempotent per (task, runner); 400 if malformed or the signature fails |
| `GET /v1/bundles/{sha256-hex}` | | 200 `application/octet-stream`, or 404 |

Task ids are `[A-Za-z0-9_-]{1,128}`. Lease durations are clamped server-side to 1 s to 24 h. Bodies over 256 MiB get 413.

Runners poll `GET /v1/tasks`, choose locally which task to take (their policy, shares and caps decide), claim it, heartbeat while running, then submit the result. With several coordinators in the config (`queues`), a task is claimed from, heartbeated at and answered to the coordinator it was listed by; a coordinator that is down is skipped.

## Not in v1

- Posting tasks and bundles over HTTP (projects use `toto post-task`, which writes to a spool directory the server serves).
- The project registry, the public ledger and per-runner authentication (ADR 8): the single bearer token only keeps strangers out of a pilot.
- Long polling or push; runners poll.
