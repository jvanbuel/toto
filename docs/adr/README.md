# Architecture decision records

| # | Decision | Status |
| --- | --- | --- |
| 1 | [Runners pull task leases](0001-runners-pull-leases.md) | Proposed |
| 2 | [Execute tasks on the contributor's machine](0002-execute-on-contributor-machine.md) | Proposed |
| 3 | [Sign tasks and results end to end](0003-sign-tasks-and-results.md) | Proposed |
| 4 | [Use Omnigent as the harness layer](0004-omnigent-as-harness-layer.md) | Proposed |
| 5 | [Harness outside, task inside the sandbox](0005-harness-outside-task-inside-sandbox.md) | Proposed |
| 6 | [Verify by redundancy and review before proofs](0006-redundancy-and-review-before-proofs.md) | Proposed |
| 7 | [Curate project intake](0007-curated-project-intake.md) | Proposed |

ADRs 2 and 5 are load-bearing: together they guarantee credentials never leave the contributor's machine. Several ADRs list a simpler v1 option worth considering before building the full design.
