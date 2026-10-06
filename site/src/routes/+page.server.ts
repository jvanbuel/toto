import { load as loadDirectory } from '#lib/directory.js';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = () => {
	const d = loadDirectory();
	return { updated: d.updated, projects: d.projects };
};
