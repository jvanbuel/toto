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
  sh -c 'apk add --no-cache musl-dev && cargo build --release -p toto-mcp-exec'
# result: dist/release/toto-mcp-exec
```

On Linux x86_64 you can instead use `rustup target add x86_64-unknown-linux-musl` and `cargo build --release --target x86_64-unknown-linux-musl -p toto-mcp-exec`.

## 2. Configure

```
export PATH="$PWD/target/release:$PATH"
toto init                      # ~/.config/toto (or $XDG_CONFIG_HOME/toto)
toto project-key ./pilot.key   # prints a public key: copy it
```

Edit `~/.config/toto/config.json`:

```json
"sandbox": {"kind": "docker", "image": "alpine", "bridge": "/ABSOLUTE/PATH/TO/dist/release/toto-mcp-exec"},
"harness": {"kind": "claude"},
"projects": {"pilot": "<public key from project-key>"}
```

and in `policy`: `"project_shares": {"pilot": 1}`, `"allowed_kinds": ["summarise"]`, `"available_tools": ["claude"]`, `"daily_token_cap": 200000`.

Podman: add `"bin": "podman"` to the sandbox. gVisor: add `"runtime": "runsc"` (see README for runtime setup).

## 3. Log in and run

```
toto login                                   # runs `claude setup-token`; paste the token when asked
toto post-task --key ./pilot.key docs/examples/hello-task.json
toto run --once
toto audit ~/.config/toto/state/audit.jsonl
```

`run --once` first probes the sandbox (Docker reachable, image present) and the harness (token file, `claude --version`), then processes the queue and exits.

## Optional: a task with inputs

`--bundle` packs a directory into the task's input bundle (unpacked into `/workspace` inside the container, hash-checked first):

```
mkdir -p /tmp/proj && printf 'def add(a, b):\n    return a - b\n' > /tmp/proj/calc.py
# edit docs/examples/hello-task.json: id "live-2", prompt "Fix the bug in /workspace/calc.py", then:
toto post-task --key ./pilot.key --bundle /tmp/proj docs/examples/hello-task.json
toto run --once
toto extract-result ~/.config/toto/queue/results/live-2.*.json ./fixed   # ./fixed/calc.py is the fixed file
```

## Optional: project context (skills, MCP servers)

```
mkdir -p /tmp/ctx/.claude/skills/greeter
printf -- '---\nname: greeter\ndescription: How to greet people in this project\n---\nAlways greet with "Ahoy" and nothing else.\n' > /tmp/ctx/.claude/skills/greeter/SKILL.md
echo 'Answer in one short sentence.' > /tmp/ctx/AGENTS.md
# policy: "allow_context": true   then edit hello-task.json: id "live-3", prompt "Use the greeter skill to greet me"
toto post-task --key ./pilot.key --context /tmp/ctx docs/examples/hello-task.json && toto run --once
```

This also checks the one thing unit tests cannot: that Claude Code lists the `Skill` tool alongside our MCP tools under `--tools "Skill"` and uses the skill (the answer should contain "Ahoy"). If the harness aborts with ``built-in tool `Skill` ...`` or the skill is ignored, send back the message.

## Variant: agent inside the container (credential proxy)

The same task with the agent in the container and no credential in it (ADR 12). Linux only. In `config.json`:

```json
"sandbox": {"kind": "docker", "image": "debian:bookworm-slim", "bridge": "/ABSOLUTE/PATH/TO/dist/release/toto-mcp-exec"},
"harness": {"kind": "claude", "placement": "container"}
```

`docker pull debian:bookworm-slim`, then run exactly as above (`toto run --once` also checks that your `claude` binary runs in the image). What this settles: **does Anthropic accept your subscription token through the proxy?** If it does not, you will see `authentication_failed` or 401-style errors; send the message back. To compare with an API key, put one in a 0600 file and add `"api_key_file": "/path"`. While a task runs, `docker exec toto-live-1 env` must not show any token.

## What to look for

Success: `Submitted("live-1")`; `toto extract-result ~/.config/toto/queue/results/live-1.*.json ./out` lists `file    hello.txt (...)` and `out/hello.txt` contains the line (the task's changed files come back as signed artifacts); the audit line shows `submitted` and a plausible `tokens=` figure; the result in `~/.config/toto/queue/results/` has an `output` that reports `hello from the sandbox`, `65534` for `id -u`, and an error or empty listing for `ls /home`.

Things this run is meant to settle (note what you see):

1. **Does `setup-token` work, and is `CLAUDE_CODE_OAUTH_TOKEN` accepted?** Failure shows as `authentication_failed` in the error, or a `claude exited ... no result` message.
2. **Does the CLI honour `--tools ""` (or `"Skill"`) and `--strict-mcp-config`?** The harness aborts with `built-in tool ... is enabled` or `sandbox bridge did not connect` if not. Either message is a useful result, not a crash.
3. **Is the usage figure right?** Compare `tokens=` in the audit line with the usage shown by your account (`/usage` in an interactive `claude` session).
4. **Did anything touch your personal Claude profile?** Your own `~/.claude` should be unchanged (no new sessions, no memory); the harness uses `~/.config/toto/state/claude-home`.
5. **Limits.** If you hit the subscription limit, what exactly did the CLI print? That is the missing signal for "donate only unused capacity".
6. **Isolation spot-check.** In another terminal while a task runs: `docker ps` shows one `toto-live-1` container; `docker inspect toto-live-1 --format '{{json .HostConfig.Binds}} {{json .Mounts}}'` should show only the bridge mount.

## If it fails

Send back: the full terminal output of `toto run --once`, `~/.config/toto/state/audit.jsonl`, `~/.config/toto/state/status.json`, and `claude --version`. To see the raw CLI stream, run the CLI by hand the way the harness does (arguments are listed in `src/claude_cli.rs`, `run`).

Clean up afterwards: `docker rm -f toto-live-1`, and revoke the token if you do not want to keep it (claude.ai account settings).
