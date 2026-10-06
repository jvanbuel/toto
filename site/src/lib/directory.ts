// The signed project directory, read at build time from ../directory in this repository and
// verified with the maintainers' public key before anything is rendered: the site cannot be
// built from a directory the maintainers did not sign. Runners do the same check (src/directory.rs).
import { createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export type Entry = {
	id: string;
	name: string;
	repo: string;
	description: string;
	public_key: string;
	kinds: string[];
	harness: string;
	needs_network: boolean;
	added: string;
};

export type Directory = { version: number; updated: string; projects: Entry[] };

type Envelope = {
	payload: string;
	payloadType: string;
	signatures: { keyid?: string; sig: string }[];
};

export const PAYLOAD_TYPE = 'application/vnd.toto.directory+json';
// The build runs in site/; the directory sits next to it in the repository (or wherever
// TOTO_DIRECTORY points). A path, not import.meta.url: the bundled server code moves.
const ROOT = resolve(process.env.TOTO_DIRECTORY ?? resolve(process.cwd(), '..', 'directory')) + '/';

/// DSSE pre-authentication encoding, the bytes the signature covers.
export function pae(payloadType: string, payload: Buffer): Buffer {
	const head = Buffer.from(`DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `);
	return Buffer.concat([head, payload]);
}

/// An Ed25519 raw public key as Node's crypto wants it (SubjectPublicKeyInfo DER).
function ed25519Key(hex: string) {
	const raw = Buffer.from(hex.trim(), 'hex');
	if (raw.length !== 32) throw new Error('the maintainers key must be 32 bytes of hex');
	const prefix = Buffer.from('302a300506032b6570032100', 'hex');
	return createPublicKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'spki' });
}

export function open(envelopeJson: string, maintainersHex: string): Directory {
	const env: Envelope = JSON.parse(envelopeJson);
	if (env.payloadType !== PAYLOAD_TYPE)
		throw new Error(`unexpected payload type ${env.payloadType}`);
	const payload = Buffer.from(env.payload, 'base64');
	const key = ed25519Key(maintainersHex);
	const ok = env.signatures.some((s) =>
		verify(null, pae(env.payloadType, payload), key, Buffer.from(s.sig, 'base64'))
	);
	if (!ok) throw new Error("the directory's signature does not verify with the maintainers' key");
	const d: Directory = JSON.parse(payload.toString('utf8'));
	if (d.version !== 1) throw new Error(`directory version ${d.version} is not supported`);
	return d;
}

/// The directory this checkout carries, verified. Called from prerendered loads only.
export function load(): Directory {
	return open(
		readFileSync(ROOT + 'projects.json', 'utf8'),
		readFileSync(ROOT + 'maintainers.pub', 'utf8')
	);
}

export function harnessLabel(h: string): string {
	return h === 'codex'
		? 'OpenAI API key'
		: h === 'claude-sdk' || h === 'claude'
			? 'Claude subscription or API key'
			: h || 'unknown harness';
}
