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

## Simpler v1 option

Make results pull requests: the project's normal code review and CI are the verification.
