# 2. Execute tasks on the contributor's machine

- Status: Proposed
- Date: 2026-10-04

## Context

Contributors donate capacity from their own AI subscriptions or API keys. The core promise of Tokens of Gratitude is that credentials never leave the contributor's control.

## Decision

All model usage happens on the contributor's machine, through the contributor's own tools and login, orchestrated by `togra`. The platform only ever sees tasks and results.

## Alternatives considered

- **Central pool of accounts or keys** run by the platform. Simpler operations and verification, but requires collecting credentials, conflicts with provider terms, and makes the platform a high-value target.
- **Zero-knowledge / MPC credential use**. Lets a third party use a credential without seeing it, but still needs the holder online per session and is far more complex than local execution.

## Consequences

- Credentials never cross the trust boundary; consent is enforced where the credential lives.
- Execution environments are heterogeneous (OS, hardware, tool versions).
- Capacity depends on contributors' machines being online.
- Results are harder to verify than centrally produced ones (see ADR 6).

This is the load-bearing decision of the architecture; most others follow from it.
