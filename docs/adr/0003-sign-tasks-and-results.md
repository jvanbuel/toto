# 3. Sign tasks and results end to end

- Status: Proposed
- Date: 2026-10-04

## Context

Runners execute instructions from projects they don't know, relayed by a platform they shouldn't have to fully trust. Projects receive results from runners they don't know.

## Decision

Projects sign task manifests with a project key; runners reject unsigned or tampered manifests. Runners sign results with their own runner keypair (not tied to any AI account).

## Alternatives considered

- **Trust the platform and TLS transport.** Simpler, but a compromised platform could inject tasks into every runner.

## Consequences

- Tamper evidence from project to runner and back.
- Contributors can allowlist or block projects by key.
- Requires key management: registration, rotation and revocation for both projects and runners.

## Simpler v1 option

Lean on existing identity: GitHub accounts for projects and runners, and signed commits (e.g. gitsign/Sigstore) for results. Defers custom key infrastructure; costs dependence on GitHub as identity provider.
