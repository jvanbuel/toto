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

## Implementation note (2026-10-04): DSSE

Tasks and results are signed as [DSSE](https://github.com/secure-systems-lab/dsse) envelopes with Ed25519 (`src/dsse.rs`), payload types `application/vnd.togra.task+json` and `application/vnd.togra.result+json`, key id = hex public key. The signature covers the exact payload bytes, so it does not depend on how a struct serialises (the first version signed "the JSON minus its signature field", which did). An envelope produced by the CLI was verified with an independent implementation (Python `cryptography`, PAE written from the spec text), and the spec's PAE example is a unit test. Results are self-certifying: the runner id is its public key. Artifacts travel next to the envelope and are bound by a hash inside the signed payload.
