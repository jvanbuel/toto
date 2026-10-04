# 9. Projects may supply skills and remote MCP servers, under contributor policy

- Status: Proposed
- Date: 2026-10-04

## Context

Projects get better results when a task carries more than a prompt: skills (instructions and reference files) and MCP servers (tools such as a project's issue tracker or dataset search). Both are also channels for attack. A skill is more untrusted prompt text plus files; an MCP server can be arbitrary code (stdio) or a stranger's service that steers the agent through tool results (remote).

Omnigent's agent spec (checked in v0.16.0) makes several unsafe things easy: inline MCP entries accept `command`/`args` (code run by the trusted runner, outside the sandbox), `headers` and `env` values with `${VAR}` expansion from the runner's environment (a project could ask for the contributor's API key), and `skills: all` (the default) exposes the contributor's own `~/.claude/skills` to the task agent. Its MCP server config does have a per-server `tools:` allow-list.

## Decision

Task manifests carry an optional, signed `context` with two lists, both inline so the project signature covers them:

- **Skills**: `name`, `description`, markdown `content` and optional text `files`. Names and file paths are validated (no traversal, no absolute paths, small alphabet, bounded depth).
- **MCP servers**: `name` and an `https://` `url` only. The type has no command, args, headers or env, so stdio servers and credential forwarding cannot be expressed. URLs may not contain `$`, userinfo or whitespace.

Contributor policy decides what is accepted, with deny by default: `allow_skills` (false), `allowed_mcp_hosts` (empty), `max_context_bytes` (64 KiB). A task with context is refused by any harness that does not declare support for it. The Omnigent harness builds a per-task agent from validated fields only, written as JSON (valid YAML) so nothing is interpolated, always with `skills: none` so the contributor's own skills never leak, and deletes it afterwards. Audit entries record the skill names and MCP hosts used.

## Alternatives considered

- **Allow stdio MCP servers inside the sandbox.** Needs a harness that runs MCP processes in the task sandbox; Omnigent runs them beside the CLI. Revisit if that changes.
- **Content-addressed bundles fetched separately.** Better for large skills; inline is enough for v1 and keeps signature coverage trivial.
- **Per-tool MCP allowlists in the manifest.** Omnigent supports a per-server `tools:` filter, so this is possible; not offered yet. (An earlier version of this ADR wrongly said it was not.)
- **Stdio MCP and project images.** Superseded in part by ADR 10, which runs them inside the task container.

## Consequences

- Remote MCP traffic originates from the trusted harness process, which has network access and the login. A server can see what the model sends it and can steer the agent with results, but cannot reach credentials. Contributors opt in per host.
- Skills run with the same trust as the prompt: inside the sandbox, no network.
- Result review (ADR 6) matters more for tasks with MCP servers, because their outputs are an extra injection path.
