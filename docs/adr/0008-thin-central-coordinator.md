# 8. Thin central coordinator, designed for federation

- Status: Proposed
- Date: 2026-10-04

## Context

Runners pull task leases (ADR 1) and execute locally (ADR 2), with Omnigent running on each contributor's machine (ADR 4). Something still has to hold the task queue, the registry of approved projects, and the public ledger. That component never sees credentials or runs models.

## Decision

Run one thin central coordinator for v1: an HTTP API over Postgres (or an equivalent serverless setup) that provides:

- **Task queue and leases**: projects post signed tasks; runners claim, renew and complete leases.
- **Project registry**: approved projects, their public keys and capacity budgets.
- **Ledger**: tasks run, capacity used and outcomes per project.

Design it so the server is a convenience, not a trust anchor:

- The queue API is an **open, versioned protocol**, documented independently of the implementation.
- Runners verify project signatures on manifests themselves (ADR 3); a compromised or replaced coordinator cannot forge tasks or results.
- `toto` can be configured with **multiple coordinator endpoints**, so moving to per-project queues later only changes where it polls.

### Resource shares

Contributors allocate capacity per project as **resource shares** (e.g. 60% project A, 40% project B), on top of their overall caps. `toto`'s policy engine enforces the shares locally when choosing which lease to claim, so consent stays with the contributor whether there is one coordinator or many.

### Federation path

The target for federation is BOINC's model: each project runs its own queue speaking the open protocol, and the registry acts as an *account manager* that curates projects and distributes their endpoints and keys (see ADR 7). `toto` already supports multiple endpoints and per-project shares, so this is a configuration change for runners.

## Alternatives considered

- **Federation from day one** (BOINC's model): each approved project hosts its own queue; runners subscribe to the projects they trust. No central operator or single point of trust, but cross-project fair scheduling, global contributor caps and a unified public ledger become much harder, and every project must run infrastructure.
- **GitHub as the coordinator** (issues as tasks, PRs as results). No server at all, but limited to code tasks and gives up the trust model; rejected as too narrow.

## Consequences

- One small service to host, monitor and fund (see open question on funding).
- Fair scheduling, budgets and the public ledger are straightforward.
- The coordinator is a single point of failure for availability, not for integrity: if it is down, runners idle; if it is compromised, signature checks still hold.
- Federation remains a later, incremental step rather than a rewrite.

## Update (2026-10-04): the queue protocol and a reference server

The open protocol is written down in `docs/queue-protocol.md` (version 1: list, claim, heartbeat, release, submit result, fetch bundle). `toto` has an HTTP client for it and supports several coordinators at once (`queues` in the config; claims go back to the coordinator that listed the task, a dead coordinator is skipped). `toto serve-queue` is a reference server over the spool directory for pilots and tests. The Postgres-backed coordinator, project registry, ledger, per-runner authentication and posting over HTTP are not built; ADR 1's GitHub-issues option is still open as an alternative first queue.
