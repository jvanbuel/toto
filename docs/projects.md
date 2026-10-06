# Choosing projects

Contributors decide which projects their runner supports; nothing runs for a project they have not added. The project does not have to know the contributor and the contributor does not have to interact with the project: they offer tokens, within their own limits.

## For contributors

```
toto projects add owner/name [--share 2] [--accept network] [--token-file gh.token]
toto projects list
toto projects remove <id>
```

`add` reads the project's descriptor from its GitHub repository, shows what it will do, and asks for confirmation (`--yes` to skip; it refuses to proceed without a terminal otherwise):

- the key fingerprint, to compare with what the project publishes elsewhere;
- the task kinds it posts, its share against your other projects, its queue;
- what its tasks ask for, and whether that is granted.

Adding a project trusts its key, gives it a share, allows its task kinds and adds its queue. **Nothing that widens what a task may do is granted unless you name it**: `--accept network` (its egress rules join your allowed rules), `context` (skills, instructions, `.mcp.json`), `stdio-mcp` (MCP servers that run a command in the sandbox), `mcp-hosts` (its remote MCP hosts). A task that needs something you did not accept is refused by your policy, as before. A project cannot swap its key later: adding it again with a different key is refused until you remove it. Removing leaves the allowed kinds and accepted permissions in your policy, since other projects may rely on them.

The descriptor is a convenience only. Every task is still checked against the key you trusted, and your policy decides what runs.

## For projects

Publish `.toto/project.json` on the default branch of the repository that holds your task issues:

```json
{
  "version": 1,
  "id": "acme-docs",
  "name": "Acme Docs",
  "description": "Keeps the documentation current.",
  "public_key": "<hex key from `toto project-key`>",
  "kinds": ["summarise", "docs-fix"],
  "needs": {
    "network": ["GET api.github.com/repos/acme/**"],
    "context": true,
    "stdio_mcp": false,
    "mcp_hosts": []
  },
  "environment": { "devcontainer": ".devcontainer/toto/devcontainer.json" }
}
```

`environment` names the image your tasks run in, either directly (`{"image": "ghcr.io/acme/env:1.0"}`) or by pointing at a `devcontainer.json` whose `image` key toto reads (a strict subset of the spec: `docs/project-owner-guide.md`). Without it your tasks run in the contributor's default image. The contributor sees the image when adding your project; its tasks then run in that image only.

`id` is 1-64 characters of `a-z`, `0-9`, `-`, `_`. `needs` is optional and lists only what your tasks actually use, so contributors can accept it knowingly. Egress rules use Omnigent's syntax (`METHODS host/path`).

## Finding projects

There is no directory yet. A curated list (a repository or a signed file the platform maintains, ADR 7) is the natural next step; `toto projects add` already works with any entry in it, because it only needs `owner/name`.
