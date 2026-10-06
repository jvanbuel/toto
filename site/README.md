# The directory site

A static SvelteKit site built from `../directory/projects.json`: what toto is, how to contribute, and every listed project with the command to add it. No server; GitHub Pages serves the build (`.github/workflows/site.yml`).

At build time `src/lib/directory.ts` verifies the directory's signature with `../directory/maintainers.pub`, the same check a runner makes, so the site cannot be built from a directory the maintainers did not sign.

```
npm install
npm run dev          # http://localhost:5173
npm run build        # prerenders into build/; BASE_PATH=/toto for project Pages
npm run check
```

Svelte 5, Tailwind v4, and shadcn-svelte conventions (`components.json`, the `cn` helper, the zinc theme in `src/routes/layout.css`): the few components in `src/lib/components/ui` were written to those conventions, and `npx shadcn-svelte@latest add <component>` drops more in next to them.
