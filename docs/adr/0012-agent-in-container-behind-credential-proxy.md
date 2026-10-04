# 12. Agent inside the container, behind a credential proxy

- Status: Proposed (prototyped and tested without a real credential; see "Not verified")
- Date: 2026-10-04
- Relates to: ADR 5, 10, 11

## Context

ADR 10/11 keep the agent loop and login on the host and give the agent only an MCP bridge into the container. That protects the credential but makes the project's environment a second-class citizen: the agent's native tools (shell, file edit) are off, and everything goes through a custom bridge. The simpler picture is the agent *in* the container with its native tools, as long as the credential cannot be reached from there.

## Decision

Offer a second placement, `placement: container`:

- The runner mounts the host's `claude` binary read-only at `/toto/claude` (it is a glibc binary, so the project image must be glibc-based, e.g. Debian or Ubuntu) and runs it with `docker exec`, with its built-in tools (`Bash`, `Read`, `Edit`, `Write`, `Glob`, `Grep`, and `Skill` when the project ships skills) running natively in the container.
- The container keeps `--network none`. The only way out is a credential proxy on the host, reached through a unix socket bind-mounted into the container and a loopback relay (`toto-mcp-exec relay`, `127.0.0.1:8080`). The agent is configured with `ANTHROPIC_BASE_URL` pointing at the relay and a dummy `ANTHROPIC_AUTH_TOKEN`.
- The proxy (`src/proxy.rs`) forwards only `POST /v1/messages` and `/v1/messages/count_tokens`, **replaces any credentials the client sent** with the real one (`Authorization: Bearer`, plus the `oauth-2025-04-20` beta flag for subscription tokens; or `x-api-key` for API keys), requests uncompressed responses, and counts tokens from them. That count is the usage meter's source in this mode: it does not depend on what the agent reports.
- Project context (`.mcp.json`, skills, `AGENTS.md`/`CLAUDE.md`) is unpacked into `/workspace` by the runner and joins the baseline, so unchanged context files are not returned as artifacts. Command MCP servers start inside the container; remote MCP servers are refused (no network).

## Tested (2026-10-04, no real credential, fake API upstream)

- Proxy: header replacement (client credentials, cookies and proxy-authorization stripped), endpoint allowlist (including path-traversal variants), SSE passthrough byte for byte, token counting for streamed and plain responses, size limits, chunked requests refused, error passthrough, no secret in errors or `Debug`.
- From a container: request through relay and socket reaches the upstream with the real credential; the credential is not in the container's environment, mounts or files; other endpoints get 403; no other network or loopback service is reachable.
- The real `claude 2.1.289` binary in `debian:bookworm-slim`, offline, pointed at the relay: it ran a Bash tool natively in the container as an unprivileged user with no credential in its environment, completed the conversation, and every model call carried the real credential added by the proxy.
- The full pipeline through the runner: input bundle in, context placed, agent run, only the changed file returned as a signed artifact, usage metered by the proxy. A deliberately broken expectation made the test fail, so it is not vacuous.

## Not verified

- **Whether Anthropic's API accepts a subscription OAuth token sent this way** (the CLI normally sends it itself, with its own headers). The proxy adds the `oauth-2025-04-20` flag but this is untested without a real token; API keys (`api_key_file`) are the standard case. The terms question in ADR 11 applies equally.
- macOS and Windows: the unix socket is bind-mounted into the container, which Docker Desktop's VM may not support. Linux only for now.
- gVisor and Podman with this placement.

## Consequences

- The credential never enters the container; the agent's only outbound channel is the Messages API through the proxy. What an agent can still do: send anything it knows to the model (prompts go to Anthropic under the contributor's account, as before) and return anything in its result (ADR 6 review still matters).
- Any process inside the container can use the proxy while the task runs, including a project's own MCP servers, so a malicious tool could spend the contributor's quota. The per-task usage cap applies (the harness kills the run when the proxy's count exceeds the cap, and the container is destroyed afterwards), but within the cap the spend is real.
- WebFetch/WebSearch and other built-ins are not enabled; the container has no network anyway.
- Project images need `tar` (inputs) and a glibc userland (the agent binary); in return the project gets its environment with native tools and no custom bridge.

## Variant tested: Omnigent preinstalled in the project image (2026-10-04)

The agent loop can also be Omnigent, installed in the image together with the project's tools and MCP servers (`docs/examples/omnigent-image/Dockerfile`: `python:3.12-slim` + `omnigent` + `claude-agent-sdk`, which bundles the Claude Code binary). Run as `docker exec ... omnigent run <agent> -p <prompt>` in the same hardened container behind the same proxy, with `os_env.sandbox.type: none` (the container is the sandbox).

Measured with the fake API (no real credential):

- Omnigent's server, runner and harness start and run under the full hardening (read-only root, all capabilities dropped, unprivileged user, no network, loopback only); the Claude CLI reached the proxy through the relay and finished the conversation. Omnigent's `sys_os_shell` tool ran a command as an unprivileged user inside the container; every model call carried the proxy's credential; the credential was not in the container; the proxy metered the traffic.
- Costs: the image is 943 MB; a cold `omnigent run` took about 19 s per task (the bare CLI starts in about 1.5 s).
- In this mode Omnigent disables the CLI's native tools and offers its own: 29 deferred tools including browser, policy, scheduling and agent-management tools, discovered through `ToolSearch`. The container is still the boundary, but the surface is far larger than a task needs. `tools.builtins` in the agent spec does not narrow it (it adds to the defaults); narrowing would need an Omnigent policy.
- The CLI inside the image is whatever the image bundles, not the contributor's own official install. For subscription use that weakens the "official client" assurance behind ADR 11's terms position.
- Each provider still needs its own proxy rules (allowed endpoints, auth injection, usage parser). Anthropic's are done; Codex's API-key mode looks the same (`POST /v1/responses`, bearer key, base URL overridable) and its ChatGPT mode has a configurable `chatgpt_base_url` and an account-id header, both untested.

## Update (2026-10-04): provider profiles and the Omnigent container placement

Implemented and tested offline (fake provider APIs, no real credentials):

- **Provider profiles in the proxy.** `Provider::Anthropic` (`POST /v1/messages`, `/v1/messages/count_tokens`; bearer subscription token with the `oauth-2025-04-20` flag, or `x-api-key`; usage from `message_start`/`message_delta`) and `Provider::OpenAi` (`POST /v1/responses`; bearer API key; usage from `response.completed`/`incomplete`/`failed`, with `input_tokens` already including cached tokens). Each profile has its own endpoint allowlist, so a profile never forwards the other provider's paths.
- **Codex in the container.** The real Codex 0.160 binary (static musl) ran a tool inside a container behind the OpenAI profile, with a base-URL override and a dummy key. Things that were not obvious: Codex's code mode needs a companion binary, `codex-code-mode-host`, next to the executable, so the sandbox now mounts a set of `agent_files` under `/toto/agent/` (the first is the executable); Codex wants its home directory to exist; its own sandbox is switched off inside the container (`--dangerously-bypass-approvals-and-sandbox`), because the container is the sandbox; it calls tools through a JavaScript `exec` custom tool that calls `tools.exec_command`.
- **`placement: container` for the Omnigent harness.** Omnigent and the agent CLI run inside the project's image (which must contain `omnigent`), with `os_env.sandbox.type: none`, the project's command MCP servers started inside the container, project skills found in `/workspace/.claude/skills`, and the proxy metering the run. Verified through the whole runner pipeline with the Claude harness (inputs, context, a tool call by Omnigent's own `sys_os_shell`, a single artifact returned, credential swapped, nothing in the container): Omnigent leaves nothing in `/workspace`, so artifacts are only what the task changed. Verified directly with Omnigent's **codex harness** behind the OpenAI profile: the tool ran in the container and the proxy metered it. Omnigent in container needs `executor.model` set (its model catalog discovery calls the provider API, which the proxy does not forward).

Not supported or not verified: the ChatGPT-subscription mode of Codex (the binary has a `chatgpt_base_url` and an account-id header, but token refresh would have to be handled by the proxy; `openai` needs `api_key_file` for now); real credentials with any provider; remote MCP servers in this placement; macOS and Windows.

## Update (2026-10-04): project-authored egress rules inside the container

The credential stays outside the container (the proxy); the network rules can live inside it. Verified with Omnigent 0.16.0, its `linux_bwrap` sandbox and its egress rule DSL, nested inside the hardened container with `nested_userns` enabled (`profiles/seccomp-nested-userns.json`, opt-in):

- The agent spec carries `os_env.sandbox: {type: linux_bwrap, write_paths: ["."], allow_network: true, egress_allow_private_destinations: true, egress_rules: ["POST 127.0.0.1/v1/messages", ...]}`. The tool ran as uid 65534 in a new network namespace with no network devices. A request matching a rule passed (HTTP 200 through the credential relay), a request outside the rules got 403 from Omnigent's egress proxy, and a raw socket to the relay was refused.
- Two obstacles had to be solved. Docker masks paths under `/proc`, so bwrap's fresh procfs mount fails (`Can't mount proc ... Operation not permitted`). Omnigent only binds the existing `/proc` for vetted backends; the env var that names the backend is pruned before the helper starts, but its marker directory `/run/lakebox` is autodetected, so the image creates it. This exposes only the container's own process list, because the container has its own pid namespace. Second, Omnigent refuses private and loopback destinations by default, and our relay is on loopback, so the spec sets `egress_allow_private_destinations: true`. That setting covers everything on loopback inside the container, which is only the relay.
- The image needs `bubblewrap` (see `docs/examples/omnigent-image/Dockerfile`).
- Rules that reach beyond the relay (arbitrary internet hosts) need an upstream exit that the host proxy does not provide yet. Until then the host-side proxy remains the hard limit and Omnigent's rules can only narrow what the relay already offers.
- Not verified: AppArmor `docker-default` interaction, hosts other than this Linux kernel, real credentials.

## Update (2026-10-04): network access is the project's rules, enforced by Omnigent

Decision: the host proxy is a credential boundary only (it swaps in the secret and meters usage); it does not filter general traffic. Network policy is authored by the project and enforced inside the container.

- `sandbox_profile.network_allowlist` in the signed manifest now holds Omnigent egress rules (`METHODS host/path`, e.g. `GET api.github.com/repos/org/**`). The runner only checks the syntax (`valid_egress_rule`) and that each rule appears in the contributor's `max_profile.network_allowlist` (exact match, default none).
- The docker sandbox gets a network (`--network bridge`) only when the contributor set `network = true` in the sandbox config **and** the task carries rules. Otherwise the task is refused (rules, no switch) or runs with `--network none` (no rules). Everything else stays hardened.
- The Omnigent container placement turns the rules into the nested sandbox spec (`egress_sandbox_spec`: `linux_bwrap`, `allow_network`, `egress_rules`). Private and loopback destinations stay blocked, so tools cannot reach the contributor's LAN. This needs the nested-userns profile and the image prerequisites above.
- Tested against a stand-in web server: `GET /ok` passed, another path and another method got 403 and never reached the server, and a raw socket failed.
- Limit: the rules bind the tool sandbox. The harness process and stdio MCP servers run unsandboxed inside the container and, once the container has a network, can reach anything the container can. The project's image owns that risk. The credential is not in the container.

## Update (2026-10-04): the network fence, and `toto doctor`

- The `network` option of the docker sandbox is now the *name* of a user-defined bridge that the contributor fenced with `toto net-setup --apply` (needs root): `DOCKER-USER` rules drop traffic from the bridge's subnet to RFC 1918, link-local and CGNAT ranges, an `INPUT` rule drops traffic to the host itself, and DNS is allowed only to the host's non-loopback resolvers. Task containers with egress rules run on this bridge and nothing else gets a network.
- This closes the gap noted above: the harness and stdio MCP servers, which run outside Omnigent's nested sandbox, can reach the internet but not the contributor's LAN, other containers or the host. It is host policy about *where* a container may go; *what* a task may fetch stays the project's rules.
- `probe()` verifies the fence by behaviour (a host listener plus a throwaway container that tries to connect to the gateway) and refuses to start when the connection succeeds, so a bridge that lost its rules, or Docker's default `bridge`, is refused instead of trusted. Tested live: unfenced refused, fenced accepted, script idempotent, teardown clean.
- `toto doctor` runs the setup checks independently (runner key, projects, policy, queue, sandbox, fence, nested-sandbox prerequisites, AppArmor note, credentials, harness) and exits 1 on any failure. Linux with iptables only; rootless Docker, Podman networks and macOS are not covered.
