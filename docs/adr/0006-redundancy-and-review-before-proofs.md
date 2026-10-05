# 6. Verify by redundancy and review before cryptographic proofs

- Status: Proposed
- Date: 2026-10-04

## Context

Projects need confidence that results are genuine model output for their task, not fabricated or low effort. Cryptographic provenance (zkTLS, TLSNotary) is possible for API calls but immature and hard for CLI-based subscription tools.

## Decision

V1 verifies with schema validation, task-provided tests, redundant execution for high-stakes tasks, project review, and reputation for runners and projects.

## Alternatives considered

- **zkTLS / TLSNotary provenance proofs.** Strong guarantees for API-key runs; complex, slow and not applicable to most subscription CLIs today.

## Consequences

- Simple and shippable now.
- Redundant tasks consume duplicated capacity.
- Fabricated results are contained by reputation rather than prevented.
- Revisit when provenance tooling matures.

## Prior art: BOINC

BOINC sends each work unit to several hosts and accepts a result once a project-specific validator finds a quorum. *Adaptive replication* skips the duplicate for hosts with a long clean record. We adopt the same pattern:

- Redundancy is the default for new or low-reputation runners.
- Runners with a sustained record of accepted results get single-run tasks, spot-checked at a configurable rate.
- One rejected or mismatched result drops a runner back to replicated tasks.

Unlike BOINC's deterministic computations, LLM output is not reproducible, so "agreement" cannot mean byte equality. Validators compare results by task tests, schema and project review, or use a judge step for open-ended tasks. This is why project review stays part of verification.

## Simpler v1 option

Make results pull requests: the project's normal code review and CI are the verification.

## Update (2026-10-04): review happens in the project's pull request process

Review of a result is not a toto feature. For GitHub queues, `toto results-to-pr` turns each verified result into a pull request automatically (`docs/github-queue.md`): file changes become a PR with the provenance in its description, text answers become a comment on the task issue. Maintainers review and merge with their normal tools (diffs, CI, CODEOWNERS, approvals); closing a PR is the rejection. Contributors never see the project. This replaces the idea of a toto review UI; the only contributor-side control left is the optional hold before submission (the daemon cannot ask a human, so `review_before_submit` stays refused until a file-based outbox exists). Redundancy across runners is not implemented on the GitHub queue.
