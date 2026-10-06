# toto

**toto** — *Tokens Offered To Others* — is the local runner that donates unused capacity from your own AI subscriptions or API keys to vetted public-good projects, without your credentials ever leaving your machine.

`toto` pulls signed tasks from a shared queue, runs them in a sandbox with your own AI tools, and returns signed results — within the caps and policies you set.

> *toto* was previously called `togra`.

## Status

Early design plus a runner spike. See [docs/design.md](docs/design.md) for the full design doc.

Implemented so far (milestone 1, offline): manifest signing/verification, a hardened Docker/Podman sandbox (gVisor via `runtime`), policy engine (caps, shares, quiet hours, sandbox limits), usage meter, result packaging and signing, audit log, and the task lifecycle against an in-memory queue. microVM sandbox, the Omnigent harness, the HTTP queue client and the TUI are stubbed behind traits.

```
cargo test
cargo run -- demo
```

## Sandbox runtimes

`DockerSandbox` works with Docker or Podman (`bin`), optionally under gVisor (`runtime = "runsc"`). `cargo test` runs live isolation checks for each combination and skips those whose daemon or `alpine` image is missing.

gVisor needs a runtime registered that disables its own networking, because the sandbox runs with `--network none`:

- Docker, `/etc/docker/daemon.json`: `{"runtimes":{"runsc":{"path":"/usr/bin/runsc","runtimeArgs":["--network=none"]}}}`
- Podman 4.x ignores runtime arguments in `containers.conf`; register a wrapper script that runs `runsc --network=none "$@"` instead.
- Nested VMs (such as cloud dev containers) have no KVM and gVisor's default `systrap` platform hung there; add `--platform=ptrace` (slower, but works). On bare metal keep the default.

## Running the daemon

```
toto init                  # creates ~/.config/toto with a runner key and a strict starter config
$EDITOR ~/.config/toto/config.json   # add trusted projects, allowed kinds, shares, pick a sandbox
toto install-service       # writes a systemd/launchd user unit; prints the command to enable it
toto status                # reads <state_dir>/status.json
```

Pick the sandbox in `config.json`: `{"kind":"docker","image":"alpine"}` (add `"runtime":"runsc"` for gVisor, `"bin":"podman"` for Podman), `{"kind":"bwrap"}` (Linux, no daemon or image), or `{"kind":"dir"}` (no isolation; development only). The daemon probes the sandbox at startup and refuses to run if it does not work. It also refuses `review_before_submit`, which needs the TUI.

Until the HTTP coordinator exists, the queue is a spool directory (`queue_dir`: `tasks/`, `leases/`, `results/`), and the harness is an echo placeholder until Omnigent is wired in.

## Omnigent harness

`{"harness":{"kind":"omnigent"}}` runs tasks through a local [Omnigent](https://github.com/omnigent-ai/omnigent) install (`pip install omnigent`, Python 3.12+, version pinned to 0.16.x). The daemon generates an agent with `allow_network: false`, which makes Omnigent keep the AI login with the unwrapped CLI and run all file and shell access in its own sandbox helpers (see ADR 5). It needs sandbox `dir` or `bwrap`, because Omnigent, not the `toto` sandbox, isolates the task. Token usage is read from the Omnigent server per session and enforced by the usage meter, which kills the run on overrun. Only tested with a stub CLI and a mock server so far: a real-login run is still to do.

## Project context: skills, MCP servers, instructions

A task's `context` is the SHA-256 of a tar laid out like a project root, using formats agents already know (ADR 9):

```
.mcp.json                       # {"mcpServers": {"tracker": {"command": "node", "args": ["srv.js"]}, "docs": {"type": "http", "url": "https://mcp.example.org/mcp"}}}
.claude/skills/triage/SKILL.md  # Agent Skills: frontmatter name (= directory) + description, then instructions
.claude/skills/triage/ref/...   # optional files
AGENTS.md                       # optional agent instructions
```

```
toto post-task --key pilot.key --context ./project-agent-files task.json
```

Only those paths are accepted. Everything else, notably `.claude/settings.json`, hooks, commands and agents, is refused, because Claude Code would run them on the contributor's host. In `.mcp.json`, command servers run **inside the task container**; remote servers must be https; headers, OAuth fields and `$` are refused. Contributors opt in per kind, deny by default, in the policy: `"allow_context": true`, `"allow_stdio_mcp": true` (command servers), `"allowed_mcp_hosts": ["mcp.example.org"]` (remote servers), `"max_context_bytes": 65536`. Only the Claude harness runs command servers; the Omnigent harness refuses them. The audit log records the skill names and MCP hosts each task used.

## Claude subscription harness

`{"harness":{"kind":"claude"}}` (with a Docker/Podman sandbox and `bridge` set) runs each task with the official `claude` CLI on your own Claude subscription (ADR 11). Run `toto login` once: it runs `claude setup-token` and stores the token (mode 600) next to the daemon's state. The CLI gets a cleared environment, a dedicated config directory and no built-in tools; its only tools run inside the sandbox container. Not yet run against a real login. Anthropic's terms restrict third-party products from offering claude.ai login; see ADR 11 before relying on this.

## Task inputs and outputs

A task's `inputs` is the SHA-256 of an input bundle in the queue (`bundles/<hash>`); all zeros means no inputs. The bundle is a standard tar (only regular files and directories at safe relative paths are accepted; see `src/archive.rs`). The runner checks the hash against the signed manifest, enforces `max_input_bytes` from policy, and unpacks it into the sandbox workspace (inside the container with plain `tar -x`, so the task image must provide `tar`). If the task's `output_schema.max_artifact_bytes` is greater than zero, files the agent changed, added or deleted come back in the signed result as a tar of the changed files, with deletions as OCI-style whiteouts (`.wh.<name>`), capped at that size.

```
toto post-task --key pilot.key --bundle ./repo task.json     # pack ./repo as the inputs
toto extract-result <queue>/results/<id>.<runner>.json ./out  # verify and write the changed files
```

### Agent in the container (credential proxy)

`"placement": "container"` in the claude harness config runs the agent *inside* the task container with its native tools, behind a host-side credential proxy (ADR 12): the container has no network and no credential; model calls reach the Messages API only through the proxy, which adds the real auth and counts the tokens.

```json
"sandbox": {"kind": "docker", "image": "debian:bookworm-slim", "bridge": "/abs/path/toto-mcp-exec"},
"harness": {"kind": "claude", "placement": "container"}
```

The image must be glibc-based (the host's `claude` binary is mounted into it) and provide `tar`. Use `"api_key_file": "/path/to/key"` for an API key instead of the subscription token. Linux only so far; tested with a fake API, not yet with a real credential.

### Omnigent in the container (any harness it supports)

Install Omnigent in the project image (see `docs/examples/omnigent-image/Dockerfile`) next to the project's tools and MCP servers, and let toto run it behind the credential proxy:

```json
"sandbox": {"kind": "docker", "image": "my-project-image", "bridge": "/abs/path/toto-mcp-exec"},
"harness": {"kind": "omnigent", "placement": "container", "harness": "claude-sdk", "provider": "anthropic", "model": "<model>"}
```

For Codex: `"harness": "codex"`, `"provider": "openai"`, `"api_key_file": "/path/to/key"`, `"model": "..."`, and `"agent_files": ["/path/to/codex", "/path/to/codex-code-mode-host"]` (static binaries from the `@openai/codex` package; they are mounted under `/toto/agent` and put on `PATH`). The proxy holds the credential; the container has none and no network. Tested against fake provider APIs only; costs: a larger image and about 20 s of startup per task.

## Guides

- Contributors: [docs/first-live-run.md](docs/first-live-run.md) (setup and variants), [docs/projects.md](docs/projects.md) (choosing projects).
- Project owners: [docs/project-owner-guide.md](docs/project-owner-guide.md), with a complete example in `docs/examples/project/`.
- Queues: [docs/github-queue.md](docs/github-queue.md), [docs/queue-protocol.md](docs/queue-protocol.md).
