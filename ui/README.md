# The local UI

The daemon serves this app on loopback while it runs (`ui_addr` in the config); `toto ui` prints the URL, or serves the app itself when no daemon runs. The session token lives in `state/ui.token`, mode 600, shared by both. It shows what the CLI prints (status and the pause reason, today's usage against the cap, the audit tail, the projects with what was approved for each) and does what the CLI does through the same previews: add a project by name or `owner/name` after seeing its image and agent, check a project for changes and approve the diff, stop supporting one, edit the cap, reserve, quiet hours and shares.

The build in `build/` is committed because `src/ui.rs` embeds it at compile time, so `cargo install` needs no Node. After changing the app:

```
npm install
npm run check
npm run build        # then cargo build, and commit build/
npm run dev          # http://localhost:5173, with `toto ui` running on 127.0.0.1:7707 for the API
```

For `npm run dev` the page needs the API on the same origin; add to `vite.config.ts` a `server.proxy` for `/api` to `http://127.0.0.1:7707`, or build and use `toto ui` directly.

Security: the server binds loopback only; every `/api` call must carry the token in the `x-toto-token` header, which the page keeps in session storage; `/api/events` (server-sent status events, which `EventSource` cannot send headers for) takes it as a query parameter instead. A page on another origin cannot read the token and a plain form cannot set the header, so other sites in the same browser cannot drive the runner. Pause and resume take effect within seconds. Other changes, from the page, the CLI or an editor, are picked up by the daemon before its next task; an edit that does not load or probe is reported on the page and the previous config keeps running.

Components and theme are the same as `site/` (Svelte 5, Tailwind v4, shadcn-svelte conventions).
