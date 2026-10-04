# 4. Use Omnigent as the harness layer

- Status: Accepted
- Date: 2026-10-04

## Context

Contributors use different AI tools: Claude Code, Codex, Cursor, raw API keys and others. `togra` needs to drive them non-interactively and report usage. [Omnigent](https://github.com/omnigent-ai/omnigent) is an Apache-2.0 meta-harness that already orchestrates many of these, with policies and a headless server mode.

## Decision

`togra` (Rust) owns queue, consent, verification, signing and audit. It delegates running a task to a local Omnigent server behind a `Harness` adapter trait.

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
- `togra` starts and supervises a local `omnigent server --background` and talks to it over its local API.
- The `Harness` trait stays the seam: a direct-CLI implementation remains possible as a fallback if Omnigent's direction or stability changes.
- Omnigent's own policies (spending caps, approval gates, tool restrictions) complement, but never replace, `togra`'s policy engine, which remains the source of truth for contributor consent.
- Verify that Omnigent's command execution can be routed into the `togra` sandbox (ADR 5) before relying on it.
