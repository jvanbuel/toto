# First live run: Claude subscription harness

Goal: run one task through the real chain (daemon, hardened container, MCP exec bridge, official `claude` CLI on your subscription) and confirm the claims in ADR 10 and 11 that only a real login can test. About 15 minutes, a few cents of subscription usage. Anthropic's terms restrict third-party products from offering claude.ai login (ADR 11, "Terms and risk"); this test uses your own login on your own machine.

## Prerequisites

- Rust, Docker (or Podman) running, the `claude` CLI installed, a Claude subscription.
- Pull the sandbox image: `docker pull alpine`.

## 1. Build

```
cargo build --release
```

Build the bridge as a static binary **for the architecture your containers run** (arm64 on Apple Silicon). Building inside an Alpine container works on any machine:

```
mkdir -p dist && docker run --rm -v "$PWD":/src:ro -v "$PWD/dist":/out -e CARGO_TARGET_DIR=/out -w /src rust:alpine \
  sh -c 'apk add --no-cache musl-dev && cargo build --release --bin togra-mcp-exec'
# result: dist/release/togra-mcp-exec
```

On Linux x86_64 you can instead use `rustup target add x86_64-unknown-linux-musl` and `cargo build --release --target x86_64-unknown-linux-musl --bin togra-mcp-exec`.

## 2. Configure

```
export PATH="$PWD/target/release:$PATH"
togra init                      # ~/.config/togra (or $XDG_CONFIG_HOME/togra)
togra project-key ./pilot.key   # prints a public key: copy it
```

Edit `~/.config/togra/config.json`:

```json
"sandbox": {"kind": "docker", "image": "alpine", "bridge": "/ABSOLUTE/PATH/TO/dist/release/togra-mcp-exec"},
"harness": {"kind": "claude"},
"projects": {"pilot": "<public key from project-key>"}
```

and in `policy`: `"project_shares": {"pilot": 1}`, `"allowed_kinds": ["summarise"]`, `"available_tools": ["claude"]`, `"daily_token_cap": 200000`.

Podman: add `"bin": "podman"` to the sandbox. gVisor: add `"runtime": "runsc"` (see README for runtime setup).

## 3. Log in and run

```
togra login                                   # runs `claude setup-token`; paste the token when asked
togra post-task --key ./pilot.key docs/examples/hello-task.json
togra run --once
togra audit ~/.config/togra/state/audit.jsonl
```

`run --once` first probes the sandbox (Docker reachable, image present) and the harness (token file, `claude --version`), then processes the queue and exits.

## What to look for

Success: `Submitted("live-1")`; the audit line shows `submitted` and a plausible `tokens=` figure; the result in `~/.config/togra/queue/results/` has an `output` that reports `hello from the sandbox`, `65534` for `id -u`, and an error or empty listing for `ls /home`.

Things this run is meant to settle (note what you see):

1. **Does `setup-token` work, and is `CLAUDE_CODE_OAUTH_TOKEN` accepted?** Failure shows as `authentication_failed` in the error, or a `claude exited ... no result` message.
2. **Does the CLI honour `--tools ""` and `--strict-mcp-config`?** The harness aborts with `built-in tool ... is enabled` or `sandbox bridge did not connect` if not. Either message is a useful result, not a crash.
3. **Is the usage figure right?** Compare `tokens=` in the audit line with the usage shown by your account (`/usage` in an interactive `claude` session).
4. **Did anything touch your personal Claude profile?** Your own `~/.claude` should be unchanged (no new sessions, no memory); the harness uses `~/.config/togra/state/claude-home`.
5. **Limits.** If you hit the subscription limit, what exactly did the CLI print? That is the missing signal for "donate only unused capacity".
6. **Isolation spot-check.** In another terminal while a task runs: `docker ps` shows one `togra-live-1` container; `docker inspect togra-live-1 --format '{{json .HostConfig.Binds}} {{json .Mounts}}'` should show only the bridge mount.

## If it fails

Send back: the full terminal output of `togra run --once`, `~/.config/togra/state/audit.jsonl`, `~/.config/togra/state/status.json`, and `claude --version`. To see the raw CLI stream, run the CLI by hand the way the harness does (arguments are listed in `src/claude_cli.rs`, `run`).

Clean up afterwards: `docker rm -f togra-live-1`, and revoke the token if you do not want to keep it (claude.ai account settings).
