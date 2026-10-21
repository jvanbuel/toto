# First live run

Goal: run one task through the real chain (daemon, OpenShell sandbox, the project's Omnigent agent in the project's image, credential proxy, your own subscription or API key) and confirm what only a real credential can test. About 20 minutes, a few cents of usage. Anthropic's terms restrict third-party products from offering claude.ai login (ADR 11, "Terms and risk"); this test uses your own login on your own machine.

## Prerequisites

- Docker running (OpenShell's Docker driver runs the sandboxes), and for the subscription path the `claude` CLI installed (only `claude setup-token` is used).
- Linux (x86_64, arm64) with Landlock enabled (any recent distribution kernel), or macOS on Apple silicon with Docker Desktop. macOS is the first run of that path: note anything that differs.

## 1. Install

From a release: `curl -fsSL https://raw.githubusercontent.com/jvanbuel/toto/main/scripts/install.sh | sh` installs toto with its pinned OpenShell.

From source:

```
scripts/pin-openshell.sh 0.1.5   # once, until a release has filled openshell.lock.toml's checksums
cargo build --release
```

and after `toto init` below, `toto openshell install` downloads the pinned OpenShell binaries and checks each against the lock.

## 2. Configure

```
export PATH="$PWD/target/release:$PATH"
toto init                      # ~/.config/toto (or $XDG_CONFIG_HOME/toto)
```

In `~/.config/toto/config.json`:

```json
"sandbox": {"kind": "openshell"},
"harness": {"kind": "omnigent", "provider": "anthropic"}
```

`toto init` writes this already. Behind an HTTP proxy, add `"upstream_proxy": {"url": "http://proxy:3128"}` (plus `"ca_bundle"` for a TLS-intercepting one) to the sandbox. OpenAI instead of Anthropic: `"provider": "openai", "api_key_file": "/path/to/key"` (mode 600).

```
toto login                     # Anthropic: runs `claude setup-token`; paste the token when asked
```

## 3. A project to run

Use a real project (`toto projects add owner/name --token-file gh.token`, see `docs/projects.md`) or make a scratch one from the example: copy `docs/examples/project/` into a repository of your own, put the public key from `toto project-key ./pilot.key` into `customizations.toto.public_key`, build and push the image named in `customizations.toto.image` (dropping `image` makes toto prebuild it, which for now needs the deprecated `docker` sandbox and its network fence, below), and add it:

```
toto projects add you/scratch --token-file gh.token
toto doctor
```

`doctor` checks the runner key, the projects, the policy, the queue, the OpenShell binaries, Landlock, toto's gateway (it starts it if the daemon is not running), each networked agent's egress rules, and the credential, and exits 1 on any `FAIL`.

## 4. Post a task and run

```
toto post-task --key ./pilot.key --github you/scratch --github-token-file gh.token --bundle ./inputs docs/examples/project/task.json
toto run --once
toto audit ~/.config/toto/state/audit.jsonl
```

`run --once` probes the sandbox and the harness, then processes the queue and exits. `toto run` without `--once` is the daemon: it also serves the local page and prints its URL; `toto pause` and `toto resume` work while it runs. The result lands as a comment on the task issue; `toto results-to-pr you/scratch --project <id>=<hex>` opens it as a pull request, or `toto github-results you/scratch --out results/` and `toto extract-result results/<id>.<runner>.json ./out` write the changed files locally.

## Variant: an agent with egress rules

If the project's agent declares egress rules (`os_env.sandbox` with `allow_network: true` and `egress_rules`, such as `GET pypi.org/simple/**`), toto turns them into OpenShell policy rules: the agent's requests reach exactly those methods and paths over HTTPS, and everything else is refused with `policy_denied`. Nothing to set up on your side. An agent that needs a network but lists no rules is refused.

## What to look for

Success: `Submitted(<id>)` from `run --once`; the audit line shows `submitted` and a plausible `tokens=` figure; the pull request or extracted files contain the change.

Things this run is meant to settle (note what you see):

1. **Does Anthropic accept the subscription token through the proxy?** The proxy adds the token and the OAuth beta flag itself. Failure shows as `authentication_failed` or a 401 in the harness error. If it fails, compare with an API key (`api_key_file`).
2. **Is the usage figure right?** Compare `tokens=` in the audit line with what your account shows.
3. **Did anything touch your personal profile?** Your own `~/.claude` should be unchanged; the agent runs in the sandbox with `HOME=/tmp/home`.
4. **Limits.** `toto status` after a task should show nothing paused while your usage is below the reserve (`policy.reserve_pct`, default 20%). If you run a task while your subscription window is nearly used up, the runner should pause with the reason and the reset time, and the task should reappear in the queue rather than fail. The headers this relies on (`anthropic-ratelimit-unified-*` for subscriptions, `anthropic-ratelimit-*` for API keys) are read from real responses only here, so note what `toto status` and the audit log say.
5. **Isolation spot-check.** While a task runs: `toto openshell status` shows the gateway running; `docker ps` shows the sandbox and its supervisor, labelled `openshell.sandbox_namespace=toto-…`; no container's environment (`docker inspect … --format '{{json .Config.Env}}'`) holds your token.
6. **macOS only:** does the sandbox start under Docker Desktop, and do the egress rules hold? The gateway's log is `~/.config/toto/state/openshell/gateway/gateway.log`.

## If it fails

Send back: the full output of `toto run --once`, `toto doctor` and `toto openshell status`, `~/.config/toto/state/audit.jsonl`, `~/.config/toto/state/status.json`, the gateway log above, and `docker image inspect <image> --format '{{.Id}}'`. toto deletes its sandboxes and stops its gateway itself; revoke the token if you do not want to keep it.

## Appendix: the deprecated `docker` sandbox

`{"kind": "docker"}` is toto's earlier sandbox, kept for one release (ADR 17). Options: `"bin": "podman"` for Podman, `"runtime": "runsc"` for gVisor, `"nested_userns": true` for agents that use Omnigent's own bubblewrap sandbox, and `"network": "toto-egress"` for agents that need a network. That network is created as root with `toto net-setup --apply`, Linux only (iptables on the Docker host), and removed with `toto net-setup --remove --apply`. Prebuilds of projects without a published image use the same fence.
