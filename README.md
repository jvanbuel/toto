# togra

The local runner for **Tokens of Gratitude**: donate unused capacity from your own AI subscriptions or API keys to vetted public-good projects, without your credentials ever leaving your machine.

`togra` pulls signed tasks from a shared queue, runs them in a sandbox with your own AI tools, and returns signed results — within the caps and policies you set.

> *Togra* is Irish for "project, proposal, endeavour".

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
togra init                  # creates ~/.config/togra with a runner key and a strict starter config
$EDITOR ~/.config/togra/config.json   # add trusted projects, allowed kinds, shares, pick a sandbox
togra install-service       # writes a systemd/launchd user unit; prints the command to enable it
togra status                # reads <state_dir>/status.json
```

Pick the sandbox in `config.json`: `{"kind":"docker","image":"alpine"}` (add `"runtime":"runsc"` for gVisor, `"bin":"podman"` for Podman), `{"kind":"bwrap"}` (Linux, no daemon or image), or `{"kind":"dir"}` (no isolation; development only). The daemon probes the sandbox at startup and refuses to run if it does not work. It also refuses `review_before_submit`, which needs the TUI.

Until the HTTP coordinator exists, the queue is a spool directory (`queue_dir`: `tasks/`, `leases/`, `results/`), and the harness is an echo placeholder until Omnigent is wired in.
