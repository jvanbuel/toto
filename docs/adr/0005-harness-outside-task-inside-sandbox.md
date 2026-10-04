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

## Findings: Omnigent v0.16.0 (checked 2026-10-04 against the PyPI wheel)

Read from source (`omnigent/inner/claude_sdk_executor.py`, `bwrap_sandbox.py`, `credential_proxy.py`) and measured with `scripts/probe-omnigent-sandbox.py` (stub CLI, fake credentials file, real bwrap). Not yet exercised against a live Claude login.

- **Default (wrapped) mode violates this ADR for the Claude subscription CLI.** Omnigent wraps the Claude CLI itself in bwrap/Seatbelt and binds `~/.claude.json` and `~/.claude/.credentials.json` (the OAuth token) into the sandbox, writable so the CLI can refresh it. Anything running in that process tree, including the Bash tool, can read the token. API keys are passed in through the environment allowlist (`env_passthrough`).
- **Its credential proxy does not cover our providers.** The egress proxy keeps secrets outside the sandbox, but only injects `Authorization: Bearer/Basic` (presets for git/gh/Databricks). Anthropic's API authenticates with `x-api-key`, so a swap-on-access binding is not available.
- **Unwrapped mode matches this ADR.** When the sandbox denies network (or cannot wrap the CLI), Omnigent runs the CLI unwrapped with native tools disabled; file and shell access then go only through its separately sandboxed `sys_os_*` helpers. Credentials stay outside, commands run inside. `allow_network: false` selects it deliberately, and the probe confirmed: the CLI runs unwrapped with native tools disabled, while a command run through the sandbox helper path with the network denied cannot see the credentials file and has only a loopback interface. In the default mode (network allowed) the probe's stub CLI read the fake token. It remains a degradation path rather than a documented configuration, so it could change between releases; pin the version and keep the probe as a regression check.
- Its sandbox backends (bwrap with seccomp and dotfile masking, Seatbelt) are more thorough than ours but only cover Linux and macOS, and cannot be swapped for Docker or gVisor.

**Consequence:** do not enable the Omnigent harness for subscription providers until unwrapped mode is also confirmed with a real login (the probe used a stub CLI). Keep `toto`'s own sandbox as the source of truth for the workspace.
