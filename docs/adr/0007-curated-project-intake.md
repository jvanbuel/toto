# 7. Curate project intake

- Status: Proposed
- Date: 2026-10-04

## Context

Contributors donate personal capacity and run tasks on their own machines. They need confidence that it goes to genuine public-good work and that projects won't abuse runners.

## Decision

Projects apply and are approved by a review board against published criteria, with a probation period, capacity budget and renewal every six months.

## Alternatives considered

- **Open marketplace** where any project can post tasks. Faster growth, but invites abuse and disguised commercial work.

## Consequences

- Higher contributor trust and abuse resistance.
- Slower onboarding and ongoing board overhead.

## Prior art: BOINC account managers

In BOINC, curation lives in *account managers* (BAM!, Science United): contributors pick projects in one place and the account manager pushes that selection to their client, while projects run independently. Our review board and registry play the same role. If coordination federates later (ADR 8), the registry becomes an account manager: it keeps curating projects and distributing their endpoints and keys, without holding their queues.

## Simpler v1 option

An allowlist file of approved repositories in this repo; projects apply by pull request and maintainers approve by merging. The board can come later.

## Update (2026-10-04): contributors opt in per project

Curation says which projects are vetted; each contributor still chooses which of them to support. `toto projects add|list|remove` (`docs/projects.md`) reads a project's `.toto/project.json` descriptor and edits only the contributor's own config; permissions that widen what a task may do are granted only when named. A directory of vetted projects is not built; `add` takes any `owner/name`, so a directory only has to supply that.
