# 4. Use Omnigent as the harness layer

- Status: Accepted
- Date: 2026-10-04

## Context

Contributors use different AI tools: Claude Code, Codex, Cursor, raw API keys and others. `toto` needs to drive them non-interactively and report usage. [Omnigent](https://github.com/omnigent-ai/omnigent) is an Apache-2.0 meta-harness that already orchestrates many of these, with policies and a headless server mode.

## Decision

`toto` (Rust) owns queue, consent, verification, signing and audit. It delegates running a task to a local Omnigent server behind a `Harness` adapter trait.

## Alternatives considered

- **Own adapter per CLI.** Full control and no Python dependency, but every new tool is new code to write and maintain.
- **Shell out directly to vendor CLIs** (`claude -p`, `codex exec`). Minimal, fine for two or three tools.

## Consequences

- Many harnesses supported from day one; policy features come for free.
- Adds a Python 3.12+ runtime next to the Rust binary.
- Omnigent is alpha; pin versions and keep it swappable behind the trait.
- Licence: Apache 2.0 permits this use; ship its licence/NOTICE, mark modified files, and don't use its name as branding.

## Implementation notes

- Omnigent is the primary `Harness` implementation from v1, not a later addition.
- `toto` starts and supervises a local `omnigent server --background` and talks to it over its local API.
- The `Harness` trait stays the seam: a direct-CLI implementation remains possible as a fallback if Omnigent's direction or stability changes.
- Omnigent's own policies (spending caps, approval gates, tool restrictions) complement, but never replace, `toto`'s policy engine, which remains the source of truth for contributor consent.
- Verified 2026-10-04: Omnigent cannot route command execution into an external sandbox; its default mode puts the Claude login inside its own. See the findings in ADR 5.

- `OmnigentHarness` (src/omnigent.rs) drives `omnigent run <agent.yaml> --harness claude-sdk -p <prompt>` as a subprocess (stdout is the answer; the session id is on stderr) and reads per-session tokens from `GET /v1/sessions/{id}`. It generates an agent with `allow_network: false` (ADR 5), pins the Omnigent version, and is not yet verified against a real login.
