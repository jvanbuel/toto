# Architecture decision records

| # | Decision | Status |
| --- | --- | --- |
| 1 | [Runners pull task leases](0001-runners-pull-leases.md) | Proposed |
| 2 | [Execute tasks on the contributor's machine](0002-execute-on-contributor-machine.md) | Proposed |
| 3 | [Sign tasks and results end to end](0003-sign-tasks-and-results.md) | Proposed |
| 4 | [Use Omnigent as the harness layer](0004-omnigent-as-harness-layer.md) | Accepted |
| 5 | [Harness outside, task inside the sandbox](0005-harness-outside-task-inside-sandbox.md) | Superseded by 13 |
| 6 | [Verify by redundancy and review before proofs](0006-redundancy-and-review-before-proofs.md) | Proposed |
| 7 | [Curate project intake](0007-curated-project-intake.md) | Proposed |
| 8 | [Thin central coordinator, designed for federation](0008-thin-central-coordinator.md) | Proposed |
| 9 | [Projects may supply skills and remote MCP servers](0009-project-supplied-skills-and-mcp.md) | Superseded by 13 |
| 10 | [Project-defined environment, reached through an MCP exec bridge](0010-project-environment-with-exec-bridge.md) | Superseded by 13 |
| 11 | [Run tasks with the official Claude CLI on the contributor's subscription](0011-claude-subscription-harness.md) | Superseded by 13 (terms section still applies) |
| 12 | [Agent inside the container, behind a credential proxy](0012-agent-in-container-behind-credential-proxy.md) | Superseded by 13 (proxy kept) |
| 13 | [Reuse: dev container, Omnigent agent directory, hardened container runtime](0013-devcontainer-omnigent-reuse.md) | Accepted |
| 14 | [Donate only unused capacity: pause at a reserve read from the provider's responses](0014-pause-at-the-reserve.md) | Accepted |
| 15 | [The contributor's UI is a local page served by the toto binary](0015-local-ui-in-the-binary.md) | Accepted |
| 16 | [Task intake, refinement and tracking through Inbound and Outbound connectors](0016-task-intake-refinement-and-tracking.md) | Proposed |

ADRs 2 and 13 are load-bearing: together they guarantee credentials never leave the contributor's machine. Several ADRs list a simpler v1 option worth considering before building the full design.
