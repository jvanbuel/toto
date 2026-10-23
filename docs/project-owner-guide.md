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

toto runs tasks in the dev container your developers use. Keep one `.devcontainer/devcontainer.json`; add a `customizations.toto` block (section 3). **You publish the image; contributors pull it** and approve it by **digest**. They never build your code (ADR 17).

**Prebuild and publish it in your CI.** Copy `docs/examples/project/.github/workflows/toto-image.yml`. It runs `toto project image --push`, which prebuilds your dev container with the reference CLI the way GitHub Codespaces makes a prebuild, then pushes it where `customizations.toto.image` names it (fully qualified, with a registry and a tag: `ghcr.io/acme/toto-env:1.0`). The prebuild phase is:
- `build` and `features`;
- then `onCreateCommand` and `updateContentCommand`, run in the container;
- the result snapshotted, starting with your image's own entrypoint and command.

Put installs in `onCreateCommand`. `postCreateCommand`, `postStartCommand` and `postAttachCommand` never run. Keys that act on the host (`mounts`, `runArgs`, `privileged`, `capAdd`, `securityOpt`, `initializeCommand`, `forwardPorts`, ...) are dropped, and contributors see a note for each. Everything else in the file (editor settings, your `vscode` customizations) is ignored. Make the package public so it pulls without credentials. Try it locally first: `toto project image` without `--push` builds the same snapshot.

**Or name an image you already publish.** A top-level `image` works when the file has no `build`, and so does `customizations.toto.image` for an image you build some other way. Contributors get exactly what that image contains: nothing in the file runs for them.

**Deprecated: contributor prebuilds.** A file that builds but names no published image used to be prebuilt on each contributor's machine. That needs open network access for installs, which only the deprecated `docker` sandbox can fence. It still works there for one release; on OpenShell, toto asks the contributor to ask you to publish.

What you can rely on at task time (toto runs your image in an [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) sandbox):

- tasks run as an unprivileged user (uid 65534), with Landlock and seccomp, the whole image read-only, a writable `/work` (512 MB) and `/tmp` (256 MB), and CPU, memory and time limits from the manifest;
- there is **no network** except the exact methods, hosts and paths your agent config lists as egress rules (section 2), enforced per request;
- the contributor's credential is never in the sandbox: model calls go to a proxy on the contributor's host, which adds it;
- inputs arrive in `/work`, the working directory; only files the task changed there come back, as artifacts, within your `max_artifact_bytes`.

The image must contain `omnigent` (and so `python3`) and the harness it drives (`claude-agent-sdk`, which bundles the Claude Code binary, or Codex), plus `sh` and `tar`. Run it as root in the Dockerfile if you like; toto starts it as uid 65534 regardless, so make sure your tools work for an unprivileged user with a writable `/tmp` and `/work` and nothing else (`HOME` is `/tmp/home`).

**Contributors approve what you publish, by content.** `toto projects add` shows the image's digest (or id), user, environment, size and build steps, read from the image itself, newest layer first, and the agent directory (section 2). The approval is bound to that content at a commit. When you publish a new image or change the agent, contributors keep running what they approved until they run `toto projects update <id>`, which shows what changed and asks again. So: write build steps that read well (a `RUN curl ... | sh` is what a reviewing contributor will judge), version your tags, and say what changed in your release notes.

## 2. The agent: an Omnigent agent directory

`.toto/agent/config.yaml` is an ordinary Omnigent agent (example in `docs/examples/project/.toto/agent/`). toto never edits it; contributors see it and approve it as is, and the runner executes `omnigent run <dir> -p <task prompt>` inside your image. What toto reads from it, and what it requires:

- `executor.config.harness`: `claude-sdk` (contributors with an Anthropic subscription or API key) or `codex` (OpenAI API key). This decides which contributors can run your tasks.
- `executor.model`: set one; the credential proxy does not forward model discovery.
- `instructions` (or `prompt`): your instructions, inline or as a file. The task's own prompt comes from the manifest. toto reads them the way Omnigent does and shows contributors the text:
  - a one-line value naming a file in the agent directory is read from that file (`instructions: prompts/system.md`);
  - with neither key set, the first of `AGENTS.md`, `CLAUDE.md` or `.cursorrules` in the agent directory is used;
  - **to reuse your repository's own AGENTS.md**, write `instructions: ../../AGENTS.md`. toto carries that one file in with the agent, at the same commit, and contributors approve it with the agent; a change to it asks them again;
  - a reference to a file that does not exist is refused (Omnigent would otherwise run the reference itself as the prompt).
- `tools`: MCP servers. A `command` runs inside your image. A `url` server needs a network, so it must be covered by your egress rules; prefer commands.
- `skills/<name>/SKILL.md`: Agent Skills, loaded by Omnigent.
- `os_env`: absent, or `type: caller_process` (anything else, such as `ssh`, is refused). Its `sandbox` is where **egress rules** live: `allow_network: true` and `egress_rules` in Omnigent's syntax (`GET docs.acme.example/**`, `GET,POST api.example.com/v1/*`). Default deny. toto turns each rule into an OpenShell policy rule, enforced per request on HTTPS from outside your image, so you need no `bubblewrap` (a `linux_bwrap` sandbox type still parses; toto runs it as `none` with OpenShell enforcing the rules). An agent that needs a network must list its destinations. Ask for as little as the task needs, and prefer `GET` on specific paths.

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
    "image": "ghcr.io/acme/toto-env:1.0",    // where `toto project image --push` publishes; contributors pull it
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

## 5. Accept requests and turn results into pull requests

Copy `docs/examples/project/.github/workflows/toto-sync.yml`, `.github/ISSUE_TEMPLATE/toto-task.yml` and `.toto/intake.toml` from the example, create the `toto:request` label, and add the secret `TOTO_PROJECT_KEY` (the hex seed `toto project-key` wrote). Every 15 minutes, and whenever an issue or comment changes, `toto project sync`:

- reads requests from the issue form (and, if you configure it, from an inbox);
- posts approved ones as signed tasks;
- turns results into **one pull request per task**;
- treats comments on the request or the pull request as refinements, each run as a further attempt on the same pull request;
- keeps a status comment on each request.

Maintainers' requests run at once; anyone else's waits for a maintainer's `/approve`, unless you list them as a pre-approved sender. **A pre-approved sender is a credential:** whoever controls that account or mailbox can spend contributors' tokens on your project, within the limits you give them. All of it is described in `docs/intake.md`.

File changes touching `.github/`, `.gitlab-ci.yml`, `.git/`, `CODEOWNERS` and similar are never applied automatically, and a cap on open toto pull requests stops a flood. Review and merge like any contribution. Give the workflow a fine-grained token (`TOTO_TOKEN`) if the pull requests should run CI. The sync keeps its state on a `toto-state` branch and never writes your default branch. Without intake, `docs/examples/toto-results.yml` (`toto results-to-pr`) still turns results of tasks you post by hand into pull requests.

## Checklist before your first task

- [ ] `.devcontainer/devcontainer.json` has `customizations.toto`, with the key from `project.key`, and the fingerprint is published elsewhere.
- [ ] The image is published (`toto project image --push` from CI) and pullable without credentials, and your `onCreateCommand` installs everything a task needs.
- [ ] `.toto/agent/config.yaml` names a harness and a model, and asks for the least network and tools it can.
- [ ] No secrets in the image, the agent directory or the bundles (assume anything a task can read, a contributor can read).
- [ ] You tried it yourself: `toto projects add` against your own repository, then `toto doctor`, then one task with `toto run --once`.
- [ ] The sync workflow runs, the `toto:request` label exists, and you know who reviews the PRs and who may `/approve`.
