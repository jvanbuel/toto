<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { Badge, Button, Card, CardSection } from '#lib/components/ui/index.js';
	import Approval from '#lib/components/approval.svelte';
	import { get, post, type Applied, type Check, type ProjectDetail } from '#lib/api.js';

	let p = $state<ProjectDetail | null>(null);
	let error = $state('');
	let busy = $state(false);
	let check = $state<Check | null>(null);
	let applied = $state<Applied | null>(null);
	const id = $derived(page.params.id ?? '');

	async function refresh() {
		try {
			p = await get<ProjectDetail>(`/projects/${id}`);
		} catch (e) {
			error = (e as Error).message;
		}
	}
	onMount(refresh);

	async function doCheck() {
		busy = true;
		error = '';
		check = null;
		applied = null;
		try {
			check = await post<Check>(`/projects/${id}/check`);
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
	async function approve() {
		if (!check || check.state !== 'changed') return;
		busy = true;
		try {
			applied = await post<Applied>(`/pending/${check.pending}/approve`);
			check = null;
			await refresh();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
	async function remove() {
		if (!confirm(`Stop supporting ${id}? Its key, share and approval are removed.`)) return;
		busy = true;
		try {
			await post<Applied>(`/projects/${id}/remove`);
			await goto(resolve('/projects'));
		} catch (e) {
			error = (e as Error).message;
			busy = false;
		}
	}
</script>

<a href={resolve('/projects')} class="text-sm text-muted-foreground hover:text-foreground"
	>← projects</a
>

{#if error}
	<p class="mt-3 rounded-md border px-3 py-2 text-sm">{error}</p>
{/if}

{#if p}
	<h1 class="mt-3 text-2xl font-semibold tracking-tight">{p.id}</h1>
	<p class="text-sm text-muted-foreground">
		{p.source ? `github:${p.source}` : 'added by hand'} · share {p.share} · key
		<span class="font-mono">{p.key.slice(0, 16)}…</span>
	</p>

	{#if p.approval}
		<Card class="mt-5">
			<CardSection>
				<h2 class="font-semibold">Approved environment and agent</h2>
				<div class="mt-3"><Approval approval={p.approval} /></div>
			</CardSection>
		</Card>
		{#if p.config_yaml}
			<Card class="mt-4">
				<CardSection>
					<h2 class="font-semibold">
						config.yaml <span class="font-normal text-muted-foreground">as approved</span>
					</h2>
					<pre class="mt-3 overflow-x-auto rounded-md bg-muted p-3 text-xs">{p.config_yaml}</pre>
					{#if p.files.length > 1}
						<p class="mt-2 text-xs text-muted-foreground">
							also: {p.files.filter((f) => f !== 'config.yaml').join(', ')}
						</p>
					{/if}
				</CardSection>
			</Card>
		{/if}
	{:else}
		<p class="mt-4 text-sm text-muted-foreground">
			No approved environment: this project was added by editing the config.
		</p>
	{/if}

	<Card class="mt-4">
		<CardSection>
			<h2 class="font-semibold">Updates</h2>
			<p class="mt-1 text-sm text-muted-foreground">
				Tasks keep running what you approved until you approve a newer version. Checking re-reads
				the repository and re-pulls the image.
			</p>
			<div class="mt-3 flex gap-3">
				<Button onclick={doCheck} disabled={busy}>{busy ? 'Checking…' : 'Check for changes'}</Button
				>
				<Button variant="outline" onclick={remove} disabled={busy}>Stop supporting</Button>
			</div>
			{#if check?.state === 'up_to_date'}
				<p class="mt-3 text-sm">
					<Badge variant="secondary">up to date</Badge>
					<span class="text-muted-foreground">{check.detail}</span>
				</p>
			{:else if check?.state === 'changed'}
				<p class="mt-3 font-medium">Changed since you approved it</p>
				<pre class="mt-2 overflow-x-auto rounded-md bg-muted p-3 text-xs">{check.lines.join(
						'\n'
					)}</pre>
				<div class="mt-3 flex gap-3">
					<Button onclick={approve} disabled={busy}>Approve this version</Button>
					<Button variant="outline" onclick={() => (check = null)}>Keep the approved one</Button>
				</div>
			{/if}
			{#if applied}
				<p class="mt-3 rounded-md border px-3 py-2 text-sm">{applied.message}</p>
			{/if}
		</CardSection>
	</Card>
{:else if !error}
	<p class="mt-3 text-sm text-muted-foreground">Loading…</p>
{/if}
