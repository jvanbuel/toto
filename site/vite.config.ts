import tailwindcss from '@tailwindcss/vite';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			adapter: adapter(),
			// Project Pages serve the site under /<repository>/; the workflow sets BASE_PATH.
			paths: { base: (process.env.BASE_PATH as '' | `/${string}` | undefined) ?? '' },
			// An empty directory leaves /projects/[id] with no pages, which is not an error here.
			prerender: { handleUnseenRoutes: 'warn' }
		})
	]
});
