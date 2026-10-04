# 11. Run tasks with the official Claude CLI on the contributor's subscription

- Status: Proposed (unit-tested against a fake CLI; not yet run against a real login)
- Date: 2026-10-04
- Builds on: ADR 5, ADR 10

## Context

Contributors want to donate unused Claude subscription capacity, not only API credit. Omnigent is a personal-use tool that launches the official CLI with whatever login it has, and exposes the login to its own sandbox (ADR 5, findings). We want the same subscription path without that exposure and without a Python runtime.

## Decision

`ClaudeCliHarness` runs the official `claude` CLI as a subprocess, one process per task:

- **Auth.** `toto login` runs `claude setup-token` (a long-lived subscription token for headless use) and stores the pasted token with mode 0600; the harness refuses a token file others can read. The token is passed to the CLI process only, in `CLAUDE_CODE_OAUTH_TOKEN`. `--bare` is never used: it ignores subscription login.
- **Isolation of the contributor's own profile.** The CLI starts with a cleared environment (so a stray `ANTHROPIC_API_KEY` cannot change who is billed), a dedicated `HOME` and `CLAUDE_CONFIG_DIR`, `--setting-sources project`, and `--strict-mcp-config`. It runs in a scratch directory containing only the task's skills.
- **Tools only in the container (ADR 10).** `--tools ""` turns off every built-in tool. The only MCP server is the runner-generated `sandbox` bridge, started as `docker exec -i <container> /toto/mcp-exec`. The prompt goes over stdin. Project MCP URLs may be added next to it (ADR 9) but cannot replace it.
- **Runtime checks.** The `system/init` event must list no built-in tool and show the bridge connected, or the run is killed.
- **Metering.** Usage is read from `assistant` events (deduplicated per message id) and the final `result`, charged to the usage meter during the run; an overrun kills the process. `system/api_retry` errors that point at the account (`rate_limit`, `account_on_hold`, `billing_error`, authentication) are named in the failure.

## Terms and risk

Anthropic's Agent SDK overview says third-party developers may not, unless previously approved, "offer claude.ai login or rate limits for their products, including agents built on the Claude Agent SDK", and points to API keys. Running strangers' tasks on contributors' subscriptions is plausibly such a product. This ADR records that the project chooses to support subscriptions anyway, with the following mitigations: subscription use is an explicit `harness.kind: "claude"` choice, never a default; the contributor's own login on their own machine is used through the official CLI, with no token extraction or sharing; and obtaining Anthropic's approval stays on the launch checklist (design doc, "Provider terms"). If approval is refused, the API-key harness is the fallback.

## Not yet verified

- A real run: `setup-token` flow, `CLAUDE_CODE_OAUTH_TOKEN` handling, the exact `stream-json` field names, and that `--tools ""` plus `--strict-mcp-config` leaves only the bridge.
- Behaviour at subscription limits: the CLI reports `rate_limit`, but "donate only unused capacity" (stop before eating into the contributor's own usage) needs a signal we have not found.
- Whether a project-supplied skill can make the CLI load other project settings (hooks in `.claude/settings.json` are not written by us, but skills could in principle contain files; validation limits paths to the skill directory).
