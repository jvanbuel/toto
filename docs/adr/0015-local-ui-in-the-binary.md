# 15. The contributor's UI is a local page served by the toto binary, not a terminal UI

- Status: Accepted
- Date: 2026-10-06
- Relates to: ADR 7 (the directory), ADR 13

## Context

Contributors choose projects, read what they approve (an image's build history, an agent config, a diff on update), set their policy and glance at status. The first three are reading-heavy; a terminal UI is worst at exactly that (no wrapping, no colour, no scrolling within a pane), and the CLI already does the commands. The design doc had planned a ratatui TUI; that was dropped on 2026-10-06.

## Decision

- `toto ui` serves a single-page SvelteKit app, embedded in the binary at compile time (`ui/build` is committed so `cargo install` needs no Node), on loopback only, and prints a URL carrying a random session token. Every API call must send the token in a header; a page on another origin cannot read it and a plain form cannot set a header, so other sites in the same browser cannot drive the runner.
- The API runs the same previews as the CLI (`projects::preview_add`, `preview_update`): a preview is computed without changing the config, shown, and applied only by a separate confirmation that names it. Policy edits are validated the same way.
- The daemon serves the page and API itself while it runs (`ui_addr`); `toto ui` serves it when no daemon runs. Pause and resume go through a marker file in the state directory that the daemon checks before each task and while it waits, so they work from the page, the CLI and a future native app alike, and a running task is never interrupted. Status changes are pushed to the page over server-sent events. The session token is a file in the state directory (mode 600) rather than a printed secret, so an app on the same account finds it. Other changes take effect when the daemon restarts, as with the CLI.
- The public site (`site/`) and the local page share components and theme (Svelte 5, Tailwind v4, shadcn-svelte conventions).

## Consequences

- One frontend stack for both the public directory site and the local page; no TUI to maintain.
- A contributor on a headless machine still has the CLI for everything; the page is a convenience, not the only path.
- The daemon does not reload its config; a later change can make it watch the file, at which point the page's "restart the daemon" note goes away.
- A native per-platform app (decided 2026-10-06, deferred until the runner has run against a real provider) is a client of this API: tray state from the event stream, pause and resume from the endpoints, the page for the detail.
