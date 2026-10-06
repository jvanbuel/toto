# 9. Projects may supply skills and remote MCP servers, under contributor policy

- Status: Superseded by ADR 13; was: Revised 2026-10-04 (supersedes the first version below)
- Date: 2026-10-04

## Revision (2026-10-04): use the existing formats

The first version below invented its own `context` structs in the manifest. They are replaced by the formats agents already use, shipped as a tar laid out like a repository root and referenced from the signed manifest by SHA-256 (like `inputs`):

- `.mcp.json`: Claude Code's MCP server config. Entries are restricted to `command`/`args`/`env` (a command to run **inside the sandbox container**, started by the runner as `docker exec -i ...`, never on the host) or `type` + `url` (a remote https server). Headers, OAuth fields, unknown keys and any value containing `$` are refused: the CLI expands `${VAR}` from its own environment, which includes the subscription token. The name `sandbox` is reserved for the runner's bridge.
- `.claude/skills/<name>/SKILL.md` and files: [Agent Skills](https://agentskills.io) (open standard). Frontmatter `name` must equal the directory.
- `AGENTS.md` / `CLAUDE.md`: agent instructions (at most 32 KiB each).

**Only exactly those paths are accepted; anything else rejects the whole bundle.** In particular `.claude/settings.json`, hooks, commands and agents are refused, because Claude Code runs hooks and similar configuration as commands on the host.

Contributor policy is still deny by default: `allow_context`, `allow_stdio_mcp` (command servers), `allowed_mcp_hosts` (remote servers, since the host connects to them), `max_context_bytes`. The runner fetches the bundle after claiming the task, checks its hash against the signed manifest, parses it and applies policy before any agent runs. Stdio MCP servers are now supported (in the container), which the first version could not do.

Limits to know: built-in tools are off, so a skill's bundled reference files are not readable by the agent unless the `Skill` tool exposes them (to verify in the live run); only the Claude harness runs command servers, and the Omnigent harness refuses them.

---

## First version (superseded)

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
