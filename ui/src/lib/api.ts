// The local server's API. The session token comes from the URL `toto ui` printed and is kept
// for the tab; every call sends it in a header, which a page on another origin cannot do.
const KEY = 'toto-token';

export function token(): string {
	const fromUrl = new URLSearchParams(location.search).get('token');
	if (fromUrl) {
		sessionStorage.setItem(KEY, fromUrl);
		history.replaceState(null, '', location.pathname + location.hash);
	}
	return sessionStorage.getItem(KEY) ?? '';
}

export class ApiError extends Error {
	status: number;
	constructor(status: number, message: string) {
		super(message);
		this.status = status;
	}
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
	const r = await fetch(`/api${path}`, {
		method,
		headers: {
			'x-toto-token': token(),
			...(body === undefined ? {} : { 'content-type': 'application/json' })
		},
		body: body === undefined ? undefined : JSON.stringify(body)
	});
	const text = await r.text();
	const json = text ? JSON.parse(text) : null;
	if (!r.ok) throw new ApiError(r.status, json?.error ?? r.statusText);
	return json as T;
}

export const get = <T>(path: string) => call<T>('GET', path);
export const post = <T>(path: string, body?: unknown) => call<T>('POST', path, body);
export const put = <T>(path: string, body: unknown) => call<T>('PUT', path, body);

export type Status = {
	state: string;
	task: string | null;
	ticks: number;
	submitted: number;
	dropped: number;
	last_error: string | null;
	paused_until: string | null;
	pause_reason: string | null;
	updated: string;
};

export type AuditEntry = {
	ts: string;
	task_id: string;
	project_id: string;
	outcome: string;
	detail: string;
	tokens: number;
};

export type Overview = {
	status: Status | null;
	used_today: number;
	daily_token_cap: number;
	reserve_pct: number;
	projects: number;
	audit: AuditEntry[];
	config_path: string;
};

export type Approval = {
	image: string;
	pinned: string;
	short: string;
	commit: string | null;
	prebuilt: boolean;
	agent_hash: string;
	harness: string;
	model: string | null;
	needs_network: boolean;
	nested_sandbox: boolean;
	skills: string[];
	mcp: [string, string][];
	egress_rules: string[];
	describe: string[];
};

export type Project = {
	id: string;
	key: string;
	share: number;
	source: string | null;
	approval: Approval | null;
};

export type ProjectDetail = Project & { config_yaml: string | null; files: string[] };

export type Preview = {
	pending: string;
	repo: string;
	id: string;
	name: string;
	description: string;
	key: string;
	kinds: string[];
	listed: boolean;
	devcontainer_notes: string[];
	approval: Approval;
	notes: string[];
	progress: string[];
};

export type Check =
	| { state: 'up_to_date'; detail: string }
	| { state: 'changed'; pending: string; lines: string[]; progress: string[] };

export type Applied = { message: string; notes: string[] };

export type Policy = {
	daily_token_cap: number;
	reserve_pct: number;
	quiet_hours: [number, number] | null;
	project_shares: Record<string, number>;
};

export function harnessLabel(h: string): string {
	return h === 'codex'
		? 'OpenAI API key'
		: h === 'claude-sdk' || h === 'claude'
			? 'Claude subscription or API key'
			: h || 'unknown harness';
}

export function fmt(n: number): string {
	return n.toLocaleString();
}
