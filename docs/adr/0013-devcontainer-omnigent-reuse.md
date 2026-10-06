# 13. Reuse: the project's dev container, an Omnigent agent directory, a hardened container runtime

- Status: Accepted (implemented and tested with fake model APIs; not yet run with a real credential)
- Date: 2026-10-06
- Supersedes: ADR 5, 9, 10, 11 (its terms section still applies), 12 (its credential proxy is kept)

## Context

By ADR 12 toto had grown three ways to run a task (the official `claude` CLI on the host with an MCP exec bridge into the container, the CLI inside the container, Omnigent inside the container), its own formats for project context (a tar of `.mcp.json`, skills and `AGENTS.md`, with per-kind contributor opt-ins), its own descriptor (`.toto/project.json`), its own subset of the dev container spec, a bubblewrap sandbox, an HTTP queue and a spool server. Each piece was tested, and together they were more code than the problem needs. The direction given for this cut: do not reinvent; projects specify a dev container, which can include MCP servers and skills; sandbox it securely; reuse Omnigent, secure container runtimes and the dev container spec.

Research into how others solve the same two problems informed the shape:

- *Setup needs a network, tasks should not.* GitHub Codespaces prebuilds capture `build`, `onCreateCommand` and `updateContentCommand` into a snapshot; `postCreate`/`postStart`/`postAttach` run later, per container. OpenAI Codex and Claude Code's cloud environments do the same two-phase thing: setup online, then the agent offline or fenced. The dev container reference CLI exposes exactly this as `devcontainer up --prebuild`.
- *Credential outside, agent inside.* Anthropic's `sandbox-runtime` (srt) and OpenAI's `codex-network-proxy` both keep the credential in a host-side proxy and give the sandbox a loopback endpoint; neither is a drop-in for toto today (srt is Node and host-oriented; `codex-network-proxy` is a Rust crate not yet published), so toto keeps its own small proxy (ADR 12) and notes the Codex crate as the preferred replacement when it is published.
- *Project-authored egress rules.* Omnigent's own sandbox (`os_env.sandbox`, bubblewrap with `egress_rules`) already enforces per-host, per-method rules around an agent's tools, inside whatever container it runs in. toto does not need its own rule engine.

## Decision

One path. A project is two standard artefacts, and toto generates nothing:

1. **`.devcontainer/devcontainer.json`**, the file the project's developers already have, with toto's block under `customizations.toto` (id, name, description, public key, task kinds, optional published `image`, agent directory). toto reads the published image from that block or the top-level `image`. With `build`/`features` and no published image, toto **prebuilds** the file on the contributor's machine with the reference dev container CLI: a sanitised override config (host-acting keys and `post*` commands dropped, toto's run flags injected: `--cap-drop=ALL`, `--security-opt=no-new-privileges`, the contributor's fenced network), `devcontainer up --prebuild`, `docker commit` with the entrypoint cleared. `onCreateCommand` and `updateContentCommand` run at prebuild and nowhere else; `postCreateCommand` and later never run.
2. **An Omnigent agent directory** (`.toto/agent`: `config.yaml` with harness, model, prompt, MCP servers, skills, and optionally `os_env.sandbox` with egress rules). toto summarises it for the contributor (harness, provider it implies, model, prompt preview, MCP servers and whether any needs a network, skills, egress rules, warnings), refuses what it cannot run (unknown harness, `os_env` other than `caller_process`, malformed rules, over 500 files or 1 MiB, unsafe paths), hashes it, and runs it as is: `omnigent run /tmp/toto-agent -p <task prompt>` inside the image.

**Approval binds content at a commit.** `toto projects add` records the image by digest (pulled) or id (prebuilt), the agent directory as a tar plus its hash, and the commit both were read at. The runner starts exactly that; `toto projects update` re-reads, shows the diff (image fields and build steps; the new agent summary) and asks again.

**The container is the sandbox; the runtime is the contributor's.** Docker or Podman with hardened flags (read-only root, all capabilities dropped, `no-new-privileges`, uid 65534, tmpfs `/workspace` and `/tmp`, pid/CPU/memory/time limits, `--entrypoint ""`, no host mounts except the relay binary and the proxy socket), optionally gVisor. `--network none` by default; an agent that needs a network (a URL MCP server, or a sandbox with `allow_network`) gets the contributor's fenced bridge (`toto net-setup`: no private ranges, no other containers, no host) or is refused.

**Egress rules live inside the sandbox.** They are the project's, in Omnigent's syntax, in the project's agent config, enforced by Omnigent's nested bubblewrap inside toto's container. toto's part is the opt-in seccomp profile that lets a nested user namespace start (`profiles/seccomp-nested-userns.json`, `nested_userns: true`), the image's `/run/lakebox` marker so bwrap can bind the container's `/proc`, and the check that rule syntax is valid before approval. The host proxy never filters traffic: it exists only to keep the credential out of the harness.

**Kept:** the credential proxy and in-container relay (ADR 12, renamed `toto-relay`), provider profiles (Anthropic, OpenAI), token metering by the proxy, the network fence, DSSE signing, GitHub issues as the queue, results to pull requests, `doctor`.

**Deleted:** the host `claude` CLI harness and host placements, the MCP exec bridge (the relay stays), the bubblewrap sandbox, context bundles and the per-kind context opt-ins (`allow_context`, `allow_stdio_mcp`, `allowed_mcp_hosts`), the manifest's `network_allowlist`, the HTTP queue and `serve-queue`, `.toto/project.json`, toto's own dev container subset, the `--accept` gates.

## Verified (2026-10-06, fake model APIs, no real credential)

- The whole runner pipeline: a project's agent directory with a skill, in the project's image (`python:3.12-slim` + omnigent + claude-agent-sdk), approved from a fake GitHub; inputs in, Omnigent runs a shell tool as uid 65534, the skill is present, the credential is not in the container (`ANTHROPIC_AUTH_TOKEN` is a dummy), every model call carries the proxy's credential, only the changed file comes back as a signed artifact, usage metered by the proxy.
- Omnigent's `codex` harness in the same shape behind the OpenAI profile.
- Egress rules from the project's config, enforced by the nested sandbox inside the container with the seccomp profile: `GET <host>/ok` allowed; other paths and methods get 403 from Omnigent's enforcement and never reach the server; a raw socket fails; the tool runs as uid 65534.
- Prebuild with the reference CLI (0.89): a Dockerfile project with `onCreateCommand` under the override config; the install is in the snapshot, the prebuild ran with `CapEff` zero, `postCreateCommand` did not run, the host mount was dropped, the task still runs as uid 65534.
- Approval and update flow: digest pinning, re-pull of moved tags, diffs; refusal of bad devcontainer files and agent configs with the reason.
- `doctor` checks approved images for `omnigent`, `tar` and `bwrap`, and the setup for what each project's agent needs.

## Not verified

- Any real credential, with either provider; whether Anthropic accepts a subscription token through the proxy (ADR 12, ADR 11's terms question).
- macOS and Windows (unix socket bind mount), Podman with the prebuild, gVisor (cannot run the nested sandbox; projects with egress rules need the default runtime).
- A prebuild that needs the fenced network from a machine without root for `net-setup`.

## Consequences

- A project owner writes nothing toto-specific beyond one JSON block and keeps a standard agent directory they can run locally with `omnigent run`. Their developers' dev container is the task environment.
- A contributor approves two things they can read: an image's build history and an agent config. Updates re-prompt. The approval is trust in the project, not proof of harmlessness; isolation and policy limit the damage.
- The prebuild runs a stranger's `onCreateCommand` on the contributor's machine, inside a container with no capabilities, no new privileges, no host mounts and the fenced network. That is the same exposure as running the task itself, accepted knowingly at `add` time, and the reason a published image is recommended.
- Fewer moving parts: one harness path, one sandbox, one queue, no custom formats. The remaining custom code is the proxy (replaceable by `codex-network-proxy` when published), the fence, signing and the queue adapters.
- Lost: running on a contributor's own official `claude` install (the CLI comes from the image), and the per-kind contributor opt-ins (replaced by approving the whole agent config). Both were judged not worth their code.
