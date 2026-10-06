# Running a project on toto

This is the guide for a project owner: the person who has work that language models can do, and wants contributors to donate unused AI capacity to it. You define the environment the work runs in and you carry the safety burden of it. The contributor's machine and credential are protected by toto whatever you put in the image, but your image, tools and prompts decide what a task can do with the files and network it is given.

A complete example is in `docs/examples/project/`. The pieces:

| Piece | File | Who reads it |
|---|---|---|
| Environment image | `environment/Dockerfile`, published by your CI | contributors' runners pull it |
| Environment pointer | `.devcontainer/toto/devcontainer.json` | `toto projects add` |
| Project descriptor | `.toto/project.json` | contributors, when they choose your project |
| Task context | skills, `AGENTS.md`, `.mcp.json` in a directory | the runner, per task |
| Tasks | issues, posted with `toto post-task --github` | runners |
| Results | pull requests, opened by `toto results-to-pr` in an Action | your maintainers |

## 1. Build the environment image

Write `environment/Dockerfile` with the harness and your tools (the example installs `omnigent`, `claude-agent-sdk` and `git`). Build and publish it from CI (`docs/examples/project/.github/workflows/toto-image.yml`) to a registry contributors can pull from, such as ghcr.io.

What toto does with it, and so what you can rely on:

- tasks run as an unprivileged user (uid 65534) in a read-only container with all capabilities dropped, a small writable `/workspace`, and CPU, memory and time limits from the manifest;
- there is **no network** unless your task carries egress rules **and** the contributor accepted them (step 4);
- the contributor's credential is never in the container: model calls go through a proxy on the host that adds it;
- inputs arrive in `/workspace`; only files the task changed there come back, as artifacts, within your `max_artifact_bytes`.

What you are responsible for: everything in the image and everything your tools do. If an MCP server in your image can delete things on a system it can reach, an injected instruction can try to make it do so. Give tasks the least they need: few tools, narrow egress rules, no secrets in the image or in task inputs (assume anything a task can read, a contributor can read).

## 2. Point toto at it

toto reads a strict subset of the dev container spec (<https://containers.dev>): the **`image`** key of a `devcontainer.json`, which must be fully qualified with a registry and a tag or digest (`ghcr.io/acme/toto-env:1.0`). Your developers' own `devcontainer.json` probably uses `build` or `features`; toto refuses files that act on the host (`mounts`, `runArgs`, `privileged`, `capAdd`, `securityOpt`, `initializeCommand`, ...) or make the contributor's machine build the image (`build`, `dockerFile`, `features`): build steps would run a stranger's code before anyone approved it, and a published image is something a contributor can inspect and pin. So keep a separate small file such as `.devcontainer/toto/devcontainer.json` that only names the published image, and let CI build the image from your normal one. Editor settings, ports and lifecycle commands in the file are ignored with a warning shown to the contributor.

**Contributors approve exactly what you publish, by digest.** When someone adds your project, `toto projects add` pulls the image, shows them its user, environment, size and build steps (read from the image itself, newest layer first) and records the image's **digest**. Their runner starts exactly that digest, whatever your tag points to later. `toto projects inspect owner/name` shows the same without changing anything, plus your `devcontainer.json`. So:

- Write build steps that read well: a `RUN curl ... | sh` is what a reviewing contributor will see and judge.
- When you publish a new image under the same tag, contributors keep running the old one until they run `toto projects update <id>`, which shows what changed (digest, user, environment, added and removed build steps) and asks them to approve. Version your tags and say what changed in your release notes, so approving an update is easy.
- The history shows *commands*, not file contents: contributors can see that you `COPY` a script, not what is in it. Keep your sources public and your image small, so they can look.

## 3. Publish the descriptor and your key

```
toto project-key project.key        # prints the public key; keep project.key secret (it signs your tasks)
```

Put `.toto/project.json` on the default branch of the repository that holds your task issues (example in `docs/examples/project/.toto/project.json`): id, name, a plain-language description, the public key, the task kinds you post, `needs` (what your tasks use, so contributors can accept it knowingly) and `environment`. Publish the key's fingerprint somewhere independent of the repository (your website, your README) so contributors can compare it when they add you.

## 4. Task context and egress rules

- **Context** is a directory laid out like a project root: `AGENTS.md` or `CLAUDE.md` (instructions), `.claude/skills/<name>/` (skills), `.mcp.json` (MCP servers: a `command` that runs in your image, or an `https` URL on a host the contributor allowed). Nothing else is accepted. `toto post-task --context dir` packs it and checks it the way a runner will.
- **Egress rules** go in the manifest's `sandbox_profile.network_allowlist`, in Omnigent's syntax: `GET docs.acme.example/**`, `GET,POST api.example.com/v1/*`. Default deny; private and loopback addresses are blocked. A contributor accepts the exact rules with `--accept network`; a task with a rule they did not accept is refused. Ask for as little as the task needs, and prefer `GET` on specific paths.

Contributors who have not accepted context or network still run your tasks that do not need them, so split tasks by what they need where you can.

## 5. Post tasks

```
toto post-task --key project.key --config cfg.json --github acme/docs \
    --github-token-file gh.token --bundle ./inputs --context ./context task.json
```

`task.json` is the manifest (`docs/examples/project/task.json`): id, kind, prompt, tool requirements, resource limits, a **cost estimate in tokens** (a task is aborted when it overruns it by the runner's margin, so estimate generously), the output schema (`max_bytes` for the text answer, `max_artifact_bytes` for files; on a GitHub queue a result must fit about 480 KB) and `redundancy`. The command signs it with your key, uploads the bundles as release assets and opens a task issue. **Resource limits:** a contributor's default ceiling is 1 CPU, 1 GiB of memory and 10 minutes per task, and a task asking for more is refused unless that contributor raised `policy.max_profile`. The example fits the defaults; ask for more only when the work needs it, and say so in your description. Inputs are the files the task works on, packed from a directory; keep them small (a contributor limits input size).

## 6. Turn results into pull requests

Copy `docs/examples/toto-results.yml` to `.github/workflows/toto-results.yml` and set the repository variable `TOTO_PROJECT` to `<id>=<hex public key>`. Every 15 minutes it opens one pull request per finished task. Review and merge like any contribution. File changes touching `.github/`, `.gitlab-ci.yml`, `.git/`, `CODEOWNERS` and similar are never applied automatically; a cap on open toto PRs stops a flood. Give the workflow a fine-grained token (`TOTO_TOKEN`) if the PRs should run CI. See `docs/github-queue.md`.

## Checklist before your first task

- [ ] The image builds in CI and a runner can pull it without credentials.
- [ ] `.devcontainer/toto/devcontainer.json` names it, with a tag.
- [ ] `.toto/project.json` is on the default branch, its key matches `project.key`, and the fingerprint is published elsewhere.
- [ ] Your tasks need the least network, context and MCP access they can, and `needs` says so.
- [ ] No secrets in the image, the bundles or the context.
- [ ] You tried a task yourself: `toto projects add` against your own repository, then `toto doctor`.
- [ ] The results Action runs, and you know who reviews the PRs.
