# Running a project on toto

This is the guide for a project owner: the person who has work that language models can do, and wants contributors to donate unused AI capacity to it. You define the environment and the agent; toto protects the contributor's machine and credential whatever you put in them, but your image, tools and prompt decide what a task can do with the files and network it is given.

Nothing here is toto-specific except one block in your `devcontainer.json` and one directory. A complete example is in `docs/examples/project/`:

| Piece | File | Format |
|---|---|---|
| Environment | `.devcontainer/devcontainer.json` (+ `Dockerfile`) | the [dev container spec](https://containers.dev), the file your developers already have |
| toto's block | `customizations.toto` in that file | id, name, description, public key, task kinds, published image, agent directory |
| Agent | `.toto/agent/` | an [Omnigent](https://github.com/omnigent-ai/omnigent) agent directory: `config.yaml` (harness, model, prompt, MCP servers, sandbox) and `skills/` |
| Tasks | issues, posted with `toto post-task --github` | signed manifests |
| Results | pull requests, opened by `toto results-to-pr` in an Action | your maintainers review them |

## 1. The environment: your dev container

toto runs tasks in the dev container your developers use. Keep one `.devcontainer/devcontainer.json`; add a `customizations.toto` block (section 3). Two ways to get an image onto contributors' machines:

**Publish it (recommended).** Build with the reference CLI in CI (`docs/examples/project/.github/workflows/toto-image.yml`: `devcontainer build --push`) and name the result in `customizations.toto.image`, fully qualified with a registry and a tag or digest (`ghcr.io/acme/toto-env:1.0`). Contributors pull it and approve it by **digest**; they never build your code. A top-level `image` works too when you have no `build`.

**Or let contributors prebuild it.** With `build` or `features` and no published image, `toto projects add` runs the dev container CLI on the contributor's machine the way GitHub Codespaces makes a prebuild: `build`, then `onCreateCommand` and `updateContentCommand`, snapshotted into an image approved by id. The prebuild runs with all capabilities dropped, `no-new-privileges` and the contributor's fenced network (so `npm ci` and `pip install` work; private addresses and the contributor's host do not). `postCreateCommand`, `postStartCommand` and `postAttachCommand` never run: put installs in `onCreateCommand`, not there. Keys that act on the host (`mounts`, `runArgs`, `privileged`, `capAdd`, `securityOpt`, `initializeCommand`, `forwardPorts`, ...) are dropped for the prebuild and never applied to tasks; the contributor sees a note for each. Everything else in the file (editor settings, your `vscode` customizations) is ignored.

Whichever way, what you can rely on at task time:

- tasks run as an unprivileged user (uid 65534) in a read-only container with all capabilities dropped, a writable `/workspace` and `/tmp`, and CPU, memory and time limits from the manifest;
- there is **no network** unless your agent config asks for one (section 2) **and** the contributor has set up the fenced network;
- the contributor's credential is never in the container: model calls go through a proxy on the host that adds it;
- inputs arrive in `/workspace`; only files the task changed there come back, as artifacts, within your `max_artifact_bytes`.

The image must contain `omnigent` (and so `python3`, which also runs toto's credential relay) and the harness it drives (`claude-agent-sdk`, which bundles the Claude Code binary, or Codex), plus `tar`. If your agent uses Omnigent's own sandbox (egress rules), also `bubblewrap` and the `/run/lakebox` marker directory; see the example Dockerfile. Run it as root in the Dockerfile if you like; toto starts it as uid 65534 regardless, so make sure your tools work for an unprivileged user with a writable `/tmp` and `/workspace` and nothing else (`HOME` is `/tmp/home`).

**Contributors approve what you publish, by content.** `toto projects add` shows the image's digest (or id), user, environment, size and build steps, read from the image itself, newest layer first, and the agent directory (section 2). The approval is bound to that content at a commit. When you publish a new image or change the agent, contributors keep running what they approved until they run `toto projects update <id>`, which shows what changed and asks again. So: write build steps that read well (a `RUN curl ... | sh` is what a reviewing contributor will judge), version your tags, and say what changed in your release notes.

## 2. The agent: an Omnigent agent directory

`.toto/agent/config.yaml` is an ordinary Omnigent agent (example in `docs/examples/project/.toto/agent/`). toto never edits it; contributors see it and approve it as is, and the runner executes `omnigent run <dir> -p <task prompt>` inside your image. What toto reads from it, and what it requires:

- `executor.config.harness`: `claude-sdk` (contributors with an Anthropic subscription or API key) or `codex` (OpenAI API key). This decides which contributors can run your tasks.
- `executor.model`: set one; the credential proxy does not forward model discovery.
- `prompt`: your instructions. The task's own prompt comes from the manifest.
- `tools`: MCP servers. A `command` runs inside your image. A `url` server needs a network, which the contributor must have fenced; prefer commands.
- `skills/<name>/SKILL.md`: Agent Skills, loaded by Omnigent.
- `os_env`: absent, or `type: caller_process` (anything else, such as `ssh`, is refused). Its `sandbox` is where **egress rules** live: `type: linux_bwrap` with `allow_network: true` and `egress_rules` in Omnigent's syntax (`GET docs.acme.example/**`, `GET,POST api.example.com/v1/*`). Default deny. This nested sandbox runs inside toto's container; it needs `bubblewrap` in your image and `nested_userns` on the contributor's side, which `toto projects add` tells them. Ask for as little as the task needs, and prefer `GET` on specific paths.

Limits: 500 files, 1 MiB; paths must be plain relative paths. A config toto cannot run (unknown harness, remote `os_env`, malformed egress rule) is refused when a contributor adds the project, with the reason.

## 3. Publish your key and the toto block

```
toto project-key project.key        # prints the public key; keep project.key secret (it signs your tasks)
```

In `.devcontainer/devcontainer.json`:

```jsonc
"customizations": {
  "toto": {
    "id": "acme-docs",                       // 1-64 of a-z 0-9 - _
    "name": "Acme Docs",
    "description": "Keeps the Acme documentation current.",
    "public_key": "<hex key from toto project-key>",
    "kinds": ["docs-fix"],                   // task kinds you post
    "image": "ghcr.io/acme/toto-env:1.0",    // published image; omit to have contributors prebuild
    "agent": ".toto/agent"                   // default
  }
}
```

Publish the key's fingerprint somewhere independent of the repository (your website, your README) so contributors can compare it when they add you, and ask to be listed in the signed project directory (`directory/README.md` in the toto repository): listed projects are added by name, and the directory carries your key, so a contributor's runner checks it for them.

## 4. Post tasks

```
toto post-task --key project.key --config cfg.json --github acme/docs \
    --github-token-file gh.token --bundle ./inputs task.json
```

`task.json` is the manifest (`docs/examples/project/task.json`): id, kind, prompt, tool requirements, resource limits, a **cost estimate in tokens** (a task is aborted when it overruns it by the runner's margin, so estimate generously), the output schema (`max_bytes` for the text answer, `max_artifact_bytes` for files; on a GitHub queue a result must fit about 480 KB) and `redundancy`. The command signs it with your key, uploads the bundle as a release asset and opens a task issue. **Resource limits:** a contributor's default ceiling is 1 CPU, 1 GiB of memory and 10 minutes per task; a task asking for more is refused unless that contributor raised `policy.max_profile`. Inputs are the files the task works on, packed from a directory; keep them small (contributors limit input size).

## 5. Turn results into pull requests

Copy `docs/examples/toto-results.yml` to `.github/workflows/toto-results.yml` and set the repository variable `TOTO_PROJECT` to `<id>=<hex public key>`. Every 15 minutes it opens one pull request per finished task. Review and merge like any contribution. File changes touching `.github/`, `.gitlab-ci.yml`, `.git/`, `CODEOWNERS` and similar are never applied automatically; a cap on open toto PRs stops a flood. Give the workflow a fine-grained token (`TOTO_TOKEN`) if the PRs should run CI. See `docs/github-queue.md`.

## Checklist before your first task

- [ ] `.devcontainer/devcontainer.json` has `customizations.toto`, with the key from `project.key`, and the fingerprint is published elsewhere.
- [ ] The image is published and pullable without credentials, or your `onCreateCommand` installs everything a task needs.
- [ ] `.toto/agent/config.yaml` names a harness and a model, and asks for the least network and tools it can.
- [ ] No secrets in the image, the agent directory or the bundles (assume anything a task can read, a contributor can read).
- [ ] You tried it yourself: `toto projects add` against your own repository, then `toto doctor`, then one task with `toto run --once`.
- [ ] The results Action runs, and you know who reviews the PRs.
