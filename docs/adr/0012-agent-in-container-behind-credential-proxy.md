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
