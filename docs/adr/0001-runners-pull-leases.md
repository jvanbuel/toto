# 1. Runners pull task leases

- Status: Proposed
- Date: 2026-10-04

## Context

Tasks must reach runners on contributors' machines. Those machines sit behind NAT and firewalls, go offline unpredictably, and are governed by the contributor's own caps and quiet hours.

## Decision

Runners pull work. A runner claims a task lease for a fixed window, renews it with heartbeats, and submits a result before it expires. Expired leases return the task to the queue.

## Alternatives considered

- **Platform pushes tasks to runners** over a persistent connection. Lower latency, but needs reachable runners or long-lived sockets, and puts the platform in charge of pacing.

## Consequences

- No inbound ports on contributor machines; works behind NAT.
- The contributor's policy engine decides when to take work, which keeps consent local.
- Polling adds latency; acceptable for batch-style public-good work.
- Lease expiry and duplicate completion must be handled (idempotent result submission).

## Simpler v1 option

Use GitHub issues in approved repositories as the queue: an issue with a `toto` label is a task, assigning it (or a claim comment) is the lease. Removes the queue server; costs race handling on claims and GitHub rate limits.
