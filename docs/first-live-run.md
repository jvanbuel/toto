# First live run

Goal: run one task through the real chain (daemon, hardened container, the project's Omnigent agent in the project's image, credential proxy, your own subscription or API key) and confirm what only a real credential can test. About 20 minutes, a few cents of usage. Anthropic's terms restrict third-party products from offering claude.ai login (ADR 11, "Terms and risk"); this test uses your own login on your own machine.

## Prerequisites

- Rust, Docker (or Podman) running, and for the subscription path the `claude` CLI installed (only `claude setup-token` is used).
- Linux or macOS (Windows with Docker Desktop should work the same, untested). On macOS, use a project with a published image and an agent that needs no network: the fence is Linux-only.

## 1. Build

```
cargo build --release
```

## 2. Configure

```
export PATH="$PWD/target/release:$PATH"
toto init                      # ~/.config/toto (or $XDG_CONFIG_HOME/toto)
```

In `~/.config/toto/config.json`:

```json
"sandbox": {"kind": "docker"},
"harness": {"kind": "omnigent", "provider": "anthropic"}
```

Podman: add `"bin": "podman"`. gVisor: add `"runtime": "runsc"` (README). OpenAI instead of Anthropic: `"provider": "openai", "api_key_file": "/path/to/key"` (mode 600).

```
toto login                     # Anthropic: runs `claude setup-token`; paste the token when asked
```

## 3. A project to run

Use a real project (`toto projects add owner/name --token-file gh.token`, see `docs/projects.md`) or make a scratch one from the example: copy `docs/examples/project/` into a repository of your own, put the public key from `toto project-key ./pilot.key` into `customizations.toto.public_key`, build and push the image named in `customizations.toto.image` (or drop `image` and let toto prebuild it; that needs the fenced network, below), and add it:

```
toto projects add you/scratch --token-file gh.token
toto doctor
```

`doctor` checks the runner key, the projects, the policy, the queue, the sandbox (including each approved image: does it contain `omnigent`, `python3`, `tar`, and `bwrap` if the agent needs it), the network fence, the nested-sandbox prerequisites and the credential, and exits 1 on any `FAIL`.

## 4. Post a task and run

```
toto post-task --key ./pilot.key --github you/scratch --github-token-file gh.token --bundle ./inputs docs/examples/project/task.json
toto run --once
toto audit ~/.config/toto/state/audit.jsonl
```

`run --once` probes the sandbox and the harness, then processes the queue and exits. `toto run` without `--once` is the daemon: it also serves the local page and prints its URL; `toto pause` and `toto resume` work while it runs. The result lands as a comment on the task issue; `toto results-to-pr you/scratch --project <id>=<hex>` opens it as a pull request, or `toto github-results you/scratch --out results/` and `toto extract-result results/<id>.<runner>.json ./out` write the changed files locally.

## Variant: an agent with egress rules

If the project's agent uses Omnigent's own sandbox (`os_env.sandbox.type: linux_bwrap` with `egress_rules`), the agent's tools reach only those hosts, enforced inside the container. The contributor side needs two things, which `toto projects add` tells you about (Linux only; the fence is iptables on the docker host): as root, `toto net-setup --apply` creates the fenced bridge `toto-egress` (no route to private ranges, other containers or this host), then set `"network": "toto-egress"` and `"nested_userns": true` in the sandbox config. `toto doctor` refuses to pass if the fence does not hold. `toto net-setup --remove --apply` undoes it. Without `network`, projects whose agent needs one are refused; without `nested_userns`, their tools fail.

## What to look for

Success: `Submitted(<id>)` from `run --once`; the audit line shows `submitted` and a plausible `tokens=` figure; the pull request or extracted files contain the change.

Things this run is meant to settle (note what you see):

1. **Does Anthropic accept the subscription token through the proxy?** The proxy adds the token and the OAuth beta flag itself. Failure shows as `authentication_failed` or a 401 in the harness error. If it fails, compare with an API key (`api_key_file`).
2. **Is the usage figure right?** Compare `tokens=` in the audit line with what your account shows.
3. **Did anything touch your personal profile?** Your own `~/.claude` should be unchanged; the agent runs in the container with `HOME=/tmp/home`.
4. **Limits.** `toto status` after a task should show nothing paused while your usage is below the reserve (`policy.reserve_pct`, default 20%). If you run a task while your subscription window is nearly used up, the runner should pause with the reason and the reset time, and the task should reappear in the queue rather than fail. The headers this relies on (`anthropic-ratelimit-unified-*` for subscriptions, `anthropic-ratelimit-*` for API keys) are read from real responses only here, so note what `toto status` and the audit log say.
5. **Isolation spot-check.** While a task runs: `docker ps` shows one `toto-<task>` container; `docker inspect toto-<task> --format '{{json .Mounts}}'` shows no mounts at all; `docker exec toto-<task> env` shows no token.

## If it fails

Send back: the full output of `toto run --once` and `toto doctor`, `~/.config/toto/state/audit.jsonl`, `~/.config/toto/state/status.json`, and `docker image inspect <image> --format '{{.Id}}'`. Clean up afterwards: `docker rm -f toto-<task>`, and revoke the token if you do not want to keep it.
