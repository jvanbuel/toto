<img src="assets/logo.svg" alt="toto" width="236" height="64">

# toto

**toto** — *Tokens Offered To Others* — is the local runner that donates unused capacity from your own AI subscriptions or API keys to projects you choose, without your credentials ever leaving your machine.

`toto` pulls signed tasks from a project's queue, runs the project's own agent in the project's own dev container on your machine, and returns signed results — within the caps and policies you set.

> *toto* was previously called `togra`.

## How it fits together

toto reuses what exists and adds as little as it can (ADR 13, ADR 17):

| Piece | Comes from | toto's part |
|---|---|---|
| Environment | the project's `.devcontainer/devcontainer.json` (the [dev container spec](https://containers.dev)) | reads `customizations.toto`; pulls the published image, or prebuilds the file with the reference CLI |
| Agent, tools, skills, prompt | the project's [Omnigent](https://github.com/omnigent-ai/omnigent) agent directory (`.toto/agent`) | shows it to the contributor, hashes it, runs it as is |
| Egress rules | the agent's Omnigent config (`os_env.sandbox.egress_rules`) | turns them into OpenShell policy rules, enforced per request (method and path) |
| Isolation | [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell): Landlock, seccomp, a policy-mediated network | ships the pinned release and runs a private gateway; nothing to set up |
| Credential | your subscription token or API key | a host-side proxy that adds it to model calls; the container never holds it |
| Queue | GitHub issues in the project's repository | signed tasks in, signed results out, results opened as pull requests |

A contributor approves exactly what will run: the image by digest (or by id when prebuilt locally) and the agent directory by hash, at a commit. A project cannot change either without the contributor approving the update.

## Status

A working runner, tested end to end with fake model APIs: Omnigent with the Claude and Codex harnesses inside an OpenShell sandbox, the credential proxy, project egress rules enforced by OpenShell, prebuilds with the dev container CLI, GitHub issues as the queue, results as pull requests. Not yet run with a real credential. See [docs/design.md](docs/design.md) and the ADRs.

```
cargo test --workspace
cargo run -- demo
```

## Contributor quick start

```
curl -fsSL https://raw.githubusercontent.com/jvanbuel/toto/main/scripts/install.sh | sh
                                            # toto plus its pinned OpenShell; needs Docker
                                            # (from source: cargo build --release && toto openshell install)
toto init                                   # ~/.config/toto: runner key, strict starter config
toto login                                  # Anthropic subscription token (or api_key_file for OpenAI)
toto directory list                         # the signed list of projects
toto projects add <name>                    # shows the image and the agent; you approve
toto doctor                                 # what works, what is missing
toto run --once                             # or: toto install-service
toto ui                                     # the local page: status, usage, projects, approvals
toto pause                                  # take no new tasks until `toto resume`
```

`config.json`, the parts you set:

```json
"sandbox": {"kind": "openshell"},
"harness": {"kind": "omnigent", "provider": "anthropic"}
```

Behind an HTTP proxy, add `"upstream_proxy": {"url": "http://proxy:3128", "ca_bundle": "/path/ca.pem"}` to the sandbox. For OpenAI: `"provider": "openai", "api_key_file": "/path"`. `{"kind": "dir"}` with `{"kind": "echo"}` is for development only. Details: [docs/first-live-run.md](docs/first-live-run.md), [docs/projects.md](docs/projects.md).

## What a task gets

- the project's image, run by OpenShell as uid 65534 with Landlock (required) and seccomp: the whole image read-only, a 512 MB `/work` and a 256 MB `/tmp`, CPU, memory and time limits from the manifest;
- no network except toto's credential proxy and, for an agent that declares them, the project's approved egress rules, each enforced per request by OpenShell's supervisor;
- the project's agent directory at `/tmp/toto-agent`, run with `omnigent run`; the task prompt from the manifest;
- model calls to toto's proxy on your host, with a per-run key instead of a credential; the proxy checks the key, adds your credential and counts tokens; the usage meter aborts a task that overruns its estimate;
- the task's input bundle unpacked into `/work`; only files the agent changed come back, as a signed artifact tar (deletions as whiteouts), capped by the task.

## Only unused capacity

The proxy sees every provider response, so it reads the rate-limit headers the provider sends: the subscription's 5-hour and 7-day window utilization, an API key's remaining requests and tokens, OpenAI's equivalents, and any 429 or 529 refusal. `policy.reserve_pct` (default 20) is the share of each window you keep for yourself: once the provider reports less than that left, or refuses a request, the runner stops claiming tasks until the window resets, and a task that was running is given back to the queue unfailed. `toto status` shows `paused` with the reason and the time, and the audit log records each pause once.

## Platforms

Linux (x86_64, arm64) and macOS (Apple silicon) with Docker: OpenShell's Docker driver runs the sandboxes. Egress rules are enforced the same way on both, so projects whose agents need a network run on macOS too. The macOS path has not been run yet (ADR 17). Projects that publish no image are prebuilt on your machine, which still needs the deprecated `docker` sandbox and its Linux network fence for now.

## The sandbox

toto runs its sandboxes on [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) (ADR 17), at the exact version, binaries and images pinned in [`openshell.lock.toml`](openshell.lock.toml), each checked by SHA-256 or digest. The daemon starts a private OpenShell gateway on `127.0.0.1:17717` and stops it on exit. Its state lives under toto's state directory, and an OpenShell you run yourself is never touched. `toto openshell status` shows the pinned version, where the binaries are and whether the gateway answers; `toto doctor` checks the rest. Options under `"sandbox"`: `bin_dir`, `port`, `upstream_proxy`, and `gateway` to use a gateway you run instead (toto then checks neither its version nor its images).

**Deprecated:** `{"kind": "docker"}`, toto's earlier hardened `docker run` with an iptables network fence and Omnigent's nested bubblewrap, works for one more release and is then removed. Its options (`bin`, `runtime`, `nested_userns`, `network`) are described in [docs/first-live-run.md](docs/first-live-run.md).

## The local page

The daemon serves a page on loopback while it runs (`ui_addr`, default `127.0.0.1:7707`); `toto ui` prints its URL, or serves the page itself when no daemon is running. It shows the runner's status and pause reason live, today's usage against the cap, the audit tail and every supported project with what was approved for it. It pauses and resumes the runner (`toto pause` and `toto resume` do the same from a terminal; a running task finishes first), adds projects, checks and approves updates, removes projects and edits the policy (the daemon picks changes up before its next task, from the page, the CLI or an editor alike), through the same previews the CLI uses: nothing is approved that was not shown. Every call carries a session token kept in `state/ui.token` (mode 600) in a header, so other users on the machine and other sites in your browser cannot drive it. The API is what a native app will talk to. See `ui/README.md`.

## Asking for work

On the project side, `toto project sync` runs in the project's own scheduled workflow. People ask for work with an issue form or by email. Maintainers and pre-approved senders are queued at once; anyone else waits for a maintainer's `/approve`. Each approved request becomes signed attempts for contributors' runners. Every task gets **one pull request**, and comments on it are refinements that run as further attempts on the same pull request. Progress shows as a status comment on the request and, optionally, on a GitHub Projects board. Its state lives on a `toto-state` branch. See [docs/intake.md](docs/intake.md) and ADR 16.

## The site

`site/` is a static SvelteKit site built from the signed directory (what toto is, how to contribute, every listed project with the command to add it), published to GitHub Pages by `.github/workflows/site.yml` whenever the directory or the site changes. The build verifies the directory's signature first, as a runner does. See `site/README.md`.

## Guides

- Contributors: [docs/first-live-run.md](docs/first-live-run.md), [docs/projects.md](docs/projects.md).
- Project owners: [docs/project-owner-guide.md](docs/project-owner-guide.md), with a complete example in `docs/examples/project/`.
- Queue: [docs/github-queue.md](docs/github-queue.md), [docs/queue-protocol.md](docs/queue-protocol.md).
- Decisions: [docs/adr/README.md](docs/adr/README.md).
- Project side: [docs/intake.md](docs/intake.md) (requests by issue form or email, refinement by comment, boards); plan: [docs/plans/intake-and-tracking.md](docs/plans/intake-and-tracking.md).
