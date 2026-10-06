# 14. Donate only unused capacity: pause at a reserve read from the provider's responses

- Status: Accepted (tested against fake providers; header semantics confirmed only for the documented API-key headers, the subscription headers are what Claude Code reads)
- Date: 2026-10-06
- Relates to: ADR 12 (the proxy sees every response), ADR 13

## Context

"Donate unused capacity" had no input. The daily token cap bounds what a contributor gives, but nothing told the runner when the contributor's own allowance was running out, so toto could spend the last of a subscription window right before the contributor wanted it, and an agent that hit a limit mid-task would retry against a closed door and then fail the task.

Every provider says this in response headers, and the credential proxy is the one component that sees every response: Anthropic subscriptions carry `anthropic-ratelimit-unified-status` and per-window utilization and reset headers (what Claude Code's `/usage` shows), API keys carry `anthropic-ratelimit-{requests,tokens,...}-{limit,remaining,reset}`, OpenAI carries `x-ratelimit-*`, and a refusal is a 429 or 529 with `retry-after`.

## Decision

- The proxy reads a `QuotaSignal` from every upstream response (`src/quota.rs`): whether the provider refused, the busiest window's utilization, the tightest limit's remaining share, and when it resets.
- The policy gets `reserve_pct` (default 20): the share of each window the contributor keeps. The runner pauses when the provider reports less than that left, or refused, until the stated reset (or `retry-after`, or five minutes when nothing is stated). A signal whose reset has passed no longer pauses; the next task refreshes it.
- A refusal during a task stops the run at once: the lease is released, the task is logged as `released` rather than failed, and it is not added to the runner's refused set, so this or another runner takes it after the reset.
- The daemon records `paused`, the reason and the time in its status file and re-checks at the reset; the audit log records each pause once.

## Consequences

- The contributor decides the reserve; projects cannot see or change it.
- The signal is only as good as the provider's headers. With none (a proxy upstream that strips them), only refusals pause the runner.
- Utilization values above 1 are read as percentages, since the subscription headers are undocumented and observed as fractions; a real-credential run should confirm the scale.
