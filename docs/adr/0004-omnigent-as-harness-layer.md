# 4. Use Omnigent as the harness layer

- Status: Proposed
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

## Simpler v1 option

Start with direct CLI adapters for one or two tools behind the same trait; adopt Omnigent when a third harness is needed.
