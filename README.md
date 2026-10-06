# toto

**toto** — *Tokens Offered To Others* — is the local runner that donates unused capacity from your own AI subscriptions or API keys to projects you choose, without your credentials ever leaving your machine.

`toto` pulls signed tasks from a project's queue, runs the project's own agent in the project's own dev container on your machine, and returns signed results — within the caps and policies you set.

> *toto* was previously called `togra`.

## How it fits together

toto reuses what exists and adds as little as it can (ADR 13):

| Piece | Comes from | toto's part |
|---|---|---|
| Environment | the project's `.devcontainer/devcontainer.json` (the [dev container spec](https://containers.dev)) | reads `customizations.toto`; pulls the published image, or prebuilds the file with the reference CLI |
| Agent, tools, skills, prompt | the project's [Omnigent](https://github.com/omnigent-ai/omnigent) agent directory (`.toto/agent`) | shows it to the contributor, hashes it, runs it as is |
| Egress rules | Omnigent's own sandbox (`os_env.sandbox`, bubblewrap) inside the container | an opt-in seccomp profile so the nested sandbox can start |
| Isolation | Docker or Podman, optionally gVisor | hardened flags: read-only, no capabilities, unprivileged user, no network unless fenced |
| Credential | your subscription token or API key | a host-side proxy that adds it to model calls; the container never holds it |
| Queue | GitHub issues in the project's repository | signed tasks in, signed results out, results opened as pull requests |

A contributor approves exactly what will run: the image by digest (or by id when prebuilt locally) and the agent directory by hash, at a commit. A project cannot change either without the contributor approving the update.

## Status

A working runner, tested end to end with fake model APIs: Omnigent with the Claude and Codex harnesses inside a hardened container, the credential proxy, project egress rules enforced by the nested sandbox, prebuilds with the dev container CLI, GitHub issues as the queue, results as pull requests. Not yet run with a real credential. See [docs/design.md](docs/design.md) and the ADRs.

```
cargo test --workspace
cargo run -- demo
```

## Contributor quick start

```
cargo build --release
toto init                                   # ~/.config/toto: runner key, strict starter config
toto login                                  # Anthropic subscription token (or api_key_file for OpenAI)
toto projects add owner/name                # shows the image and the agent; you approve
toto doctor                                 # what works, what is missing
toto run --once                             # or: toto install-service
```

`config.json`, the parts you set:

```json
"sandbox": {"kind": "docker"},
"harness": {"kind": "omnigent", "provider": "anthropic"}
```

Add `"bin": "podman"` for Podman, `"runtime": "runsc"` for gVisor, `"nested_userns": true` for projects whose agent uses Omnigent's own sandbox (egress rules), and `"network": "toto-egress"` after `toto net-setup --apply` for agents that need a network. For OpenAI: `"provider": "openai", "api_key_file": "/path"`. `{"kind": "dir"}` with `{"kind": "echo"}` is for development only. Details: [docs/first-live-run.md](docs/first-live-run.md), [docs/projects.md](docs/projects.md).

## What a task gets

- the project's image, started read-only with all capabilities dropped, `no-new-privileges`, uid 65534, a 512 MB writable `/workspace`, pid, CPU, memory and time limits from the manifest, `--network none` unless the agent needs a network and you fenced one;
- the project's agent directory at `/tmp/toto-agent`, run with `omnigent run`; the task prompt from the manifest;
- model calls through `127.0.0.1:8080` in the container, where a small Python relay (written in over `docker exec`, no mount) carries them over the exec stream to the proxy on your host, which adds your credential and counts tokens; the usage meter aborts a task that overruns its estimate;
- the task's input bundle unpacked into `/workspace`; only files the agent changed come back, as a signed artifact tar (deletions as whiteouts), capped by the task.

## Platforms

Linux, macOS and Windows hosts with Docker Desktop, Docker Engine or Podman. Nothing is mounted into a task container and it needs no network, so the relay works through Docker Desktop's VM as well. The network fence is Linux-only (iptables on the docker host): on macOS and Windows, projects whose agents need a network, and projects without a published image (which need the fence to prebuild), are refused; published images and offline agents work. `toto doctor` says which applies.

## Sandbox runtimes

`DockerSandbox` works with Docker or Podman (`bin`), optionally under gVisor (`runtime = "runsc"`). `cargo test` runs live isolation checks for each combination and skips those whose daemon or image is missing. gVisor needs a runtime registered with `--network=none` (`/etc/docker/daemon.json`: `{"runtimes":{"runsc":{"path":"/usr/bin/runsc","runtimeArgs":["--network=none"]}}}`); nested VMs without KVM need `--platform=ptrace`. gVisor cannot run Omnigent's nested sandbox, so projects with egress rules need the default runtime plus `nested_userns` (`profiles/README.md`).

## Guides

- Contributors: [docs/first-live-run.md](docs/first-live-run.md), [docs/projects.md](docs/projects.md).
- Project owners: [docs/project-owner-guide.md](docs/project-owner-guide.md), with a complete example in `docs/examples/project/`.
- Queue: [docs/github-queue.md](docs/github-queue.md), [docs/queue-protocol.md](docs/queue-protocol.md).
- Decisions: [docs/adr/README.md](docs/adr/README.md).
