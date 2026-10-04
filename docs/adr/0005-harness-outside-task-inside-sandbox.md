# 5. Harness outside, task inside the sandbox

- Status: Proposed
- Date: 2026-10-04

## Context

The AI tool needs the contributor's login. Task content (prompts, repositories, files) comes from strangers and may contain prompt injection aimed at reading credentials or host data.

## Decision

The harness runs outside the sandbox and holds the login. The task workspace lives inside an isolated sandbox with no host filesystem, no credentials and default-deny network egress. The harness acts on the workspace only; commands it executes run inside the sandbox.

## Alternatives considered

- **Tool and login inside the sandbox**, with a short-lived scoped token. Stronger isolation of the tool itself, but few providers offer scoped tokens for subscription logins.
- **Runner-side auth broker** that injects headers for model calls. Clean for API keys, harder for subscription CLIs.

## Consequences

- Task content cannot read the credential directly.
- The harness is trusted; injection can still steer what it does, so egress stays default-deny and outputs are reviewed.
- Requires harnesses whose command execution can be routed into the sandbox.
