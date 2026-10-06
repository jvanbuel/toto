# Choosing projects

Contributors decide which projects their runner supports; nothing runs for a project they have not added. The project does not have to know the contributor and the contributor does not have to interact with the project: they offer tokens, within their own limits.

## For contributors

```
toto projects add owner/name [--share 2] [--token-file gh.token] [--yes]
toto projects inspect owner/name
toto projects update <id>
toto projects list
toto projects remove <id>
```

`add` reads two things from the project's GitHub repository at its current commit: `.devcontainer/devcontainer.json` (the project's dev container, with toto's block under `customizations.toto`) and the agent directory it names (`.toto/agent`, an Omnigent agent). It then shows what will run and asks for confirmation (`--yes` to skip; it refuses to proceed without a terminal otherwise):

- the key fingerprint, to compare with what the project publishes elsewhere;
- the task kinds it posts, its share against your other projects, its queue;
- **the image**: pulled, then its digest, user, environment variables, entrypoint, size and the build steps of every layer, read from the image itself. If the project publishes no image, its dev container is **prebuilt on your machine** with the reference dev container CLI (`build`, `onCreateCommand`, `updateContentCommand`), under toto's flags (no capabilities, no new privileges, your fenced network, no host mounts), and the snapshot's id is what you approve;
- **the agent**: harness (which decides whether your credential fits), model, the first line of its prompt, each MCP server (command, or URL), skills, and the egress rules of its sandbox, if any;
- notes on anything in the dev container that toto does not apply (`runArgs`, `mounts`, `postCreateCommand`, ...), and on what your own setup lacks for this project: the fenced network, `nested_userns`, a GitHub token, a credential for the other provider.

Adding a project trusts its key, gives it a share, allows its task kinds, adds its queue and records the approval: the image by content (digest, or id when prebuilt), the agent directory by hash, and the commit both came from. Your runner starts exactly that image with exactly that agent. A project cannot swap its key later: adding it again with a different key is refused until you remove it.

**Updates.** When the project publishes a new image under the same tag or changes its agent, you keep running what you approved. `toto projects update <id>` re-reads the repository, re-pulls the tag (or prebuilds again), shows what changed (digest, user, environment, added and removed build steps; the new agent summary) and asks again. `inspect` shows all of this for any project without changing anything.

**What the approval is.** The build history lists commands, not the contents of files they copy in; a prompt and a config can read innocently and still be harmful with the right input. The approval is a decision about whether you trust the project and what it shows you, not a proof that the image or the agent is harmless. The container's isolation (read-only, unprivileged, no credential, no network unless the agent asks and you fenced one, egress rules enforced inside) is what limits the damage, and your policy (daily cap, per-task limits, kinds) limits the spend.

Every task is still checked against the key you trusted, and your policy decides what runs. Removing a project removes its key, share, approval and, if no other project uses it, its queue; allowed kinds stay, since other projects may rely on them.

## For projects

See `docs/project-owner-guide.md`. In short: your `.devcontainer/devcontainer.json` gets a `customizations.toto` block (id, name, description, public key, kinds, published image, agent directory), and `.toto/agent/` is an Omnigent agent directory. toto generates nothing and edits nothing.

## Finding projects

There is no directory yet. A curated list (a repository or a signed file the platform maintains, ADR 7) is the natural next step; `toto projects add` already works with any entry in it, because it only needs `owner/name`.
