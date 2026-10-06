import { error } from '@sveltejs/kit';
import { load as loadDirectory } from '#lib/directory.js';
import type { EntryGenerator, PageServerLoad } from './$types';

export const entries: EntryGenerator = () => loadDirectory().projects.map((p) => ({ id: p.id }));

export const load: PageServerLoad = ({ params }) => {
	const d = loadDirectory();
	const project = d.projects.find((p) => p.id === params.id);
	if (!project) error(404, 'no such project in the directory');
	return { project, updated: d.updated };
};
