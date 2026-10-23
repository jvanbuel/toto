# 18. The agent is defined in Omnigent's format, built on MCP, Agent Skills and AGENTS.md

- Status: Accepted (implemented 2026-10-23: `src/agent.rs`, `projects::carry_outside_instructions`)
- Date: 2026-10-23
- Relates to: ADR 4 (Omnigent as the harness layer), ADR 13 (the agent directory)

## Context

A project describes its agent in an Omnigent agent directory (`.toto/agent/config.yaml` and `skills/`). Before building more on it, we checked whether an open standard for defining an agent had emerged that toto should read instead (October 2026).

A toto agent definition must cover:
- the harness, which decides the contributor's credential;
- the model and the prompt;
- tools;
- skills;
- the network: what the agent may reach.

| Candidate | What it covers | Why not the agent format |
|---|---|---|
| MCP (Agentic AI Foundation, Linux Foundation) | tools | The standard for tools; toto already uses it. |
| Agent Skills (`SKILL.md`, agentskills.io) | packaged know-how | The de facto standard since December 2025, read by Claude Code, Codex, Copilot, Cursor, Gemini CLI, goose and others; toto already uses it. |
| AGENTS.md (Agentic AI Foundation) | instructions for coding agents | An instructions file, not a definition: no model, tools or network. |
| A2A agent cards (Agentic AI Foundation) | discovering and calling remote agents | About calling agents over the network, not running one. |
| Oracle Open Agent Specification | agents and workflows across LangGraph, CrewAI, AutoGen, WayFlow | Serious, but aimed at workflow frameworks; no sandbox or egress. |
| Copilot `.agent.md`, Claude Code `.claude/agents/*.md`, Docker cagent YAML | one product's agents | Each tied to its own tool, with incompatible fields. |
| Agent Format (`.agf.yaml`), OSSA, Open Agent Spec (prime-vector), Open Agent Format | full manifests | Small independent projects, one already archived; none has adoption. |

No neutral standard covers the whole definition. Omnigent's format does, and its parts are the standards above:
- tools are MCP servers;
- skills are `skills/<name>/SKILL.md`;
- `instructions: AGENTS.md` is its recommended way to give the prompt.

Omnigent is a Python package. There is no Rust crate, and toto runs Omnigent inside the project's image anyway, so Omnigent itself checks the file when a task runs.

## Decision

- **Keep Omnigent's format.** toto reads the few fields it must understand (harness, model, instructions, MCP servers, skills, egress rules) with its own small parser, and passes the directory to Omnigent otherwise unchanged. toto takes no dependency on Omnigent's code. Where toto's reading must match Omnigent's, it follows Omnigent's parser and says so in the code.
- **Instructions are resolved exactly as Omnigent resolves them**, so the contributor approves the prompt that will run:
  - `instructions` wins over its legacy alias `prompt`;
  - a one-line value is a file if that file exists inside the agent directory, and inline text otherwise;
  - with neither set, the first of `AGENTS.md`, `CLAUDE.md` or `.cursorrules` in the directory.
- **References that would silently become the prompt are refused.** Omnigent never reads outside the agent directory: a value naming a missing file, or one outside the directory, is used as the prompt text itself. toto refuses a reference to a file that is not there.
- **The repository's own AGENTS.md can be the agent's instructions.** For `instructions: ../../AGENTS.md` (any plain upward path), toto reads that one file at the approved commit and carries it in the agent directory under `.toto-repo/` (`.toto-repo/up/up/AGENTS.md`). It is shown, hashed and approved with the agent, and a change to it needs re-approval like any agent change. At task time the reference points at the carried copy. That is a derived change, like turning off Omnigent's own sandbox on OpenShell; the approved files are otherwise byte for byte what runs. `.toto-repo/` is reserved.

## Consequences

- Projects that already keep an AGENTS.md for their developers' coding agents can reuse it as the toto agent's instructions without copying it.
- toto follows Omnigent's format as Omnigent evolves. The fields toto reads are few and covered by tests, including one that runs Omnigent's own parser on what toto ships.
- Revisit when a neutral body (most likely the Agentic AI Foundation) takes on an agent-definition format. Contributors approve the agent as a hash of files, so reading a second format would not change the approval model.
