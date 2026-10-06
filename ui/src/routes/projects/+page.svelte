<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import { Badge, Button, Card, CardSection } from '#lib/components/ui/index.js';
	import Approval from '#lib/components/approval.svelte';
	import { get, post, type Applied, type Preview, type Project } from '#lib/api.js';

	let projects = $state<Project[]>([]);
	let error = $state('');
	let arg = $state('');
	let share = $state(1);
	let busy = $state(false);
	let preview = $state<Preview | null>(null);
	let applied = $state<Applied | null>(null);

	async function refresh() {
		try {
			projects = await get<Project[]>('/projects');
		} catch (e) {
			error = (e as Error).message;
		}
	}
	onMount(refresh);

	async function doPreview() {
		busy = true;
		error = '';
		applied = null;
		preview = null;
		try {
			preview = await post<Preview>('/projects/preview', { arg: arg.trim(), share });
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}

	async function approve() {
		if (!preview) return;
		busy = true;
		try {
			applied = await post<Applied>(`/pending/${preview.pending}/approve`);
			preview = null;
			arg = '';
			await refresh();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
</script>

<h1 class="text-2xl font-semibold tracking-tight">Projects</h1>
<p class="mt-1 text-sm text-muted-foreground">
	Nothing runs for a project you have not added. Adding shows you its image and its agent first.
</p>

<Card class="mt-6">
	<CardSection>
		<h2 class="font-semibold">Add a project</h2>
		<form
			class="mt-3 flex flex-wrap items-end gap-3"
			onsubmit={(e) => {
				e.preventDefault();
				doPreview();
			}}
		>
			<label class="flex flex-col gap-1 text-sm">
				<span class="text-muted-foreground">Name from the directory, or owner/name</span>
				<input
					class="h-9 w-72 rounded-md border bg-background px-3 text-sm"
					bind:value={arg}
					placeholder="acme-docs"
					required
				/>
			</label>
			<label class="flex flex-col gap-1 text-sm">
				<span class="text-muted-foreground">Share</span>
				<input
					class="h-9 w-20 rounded-md border bg-background px-3 text-sm"
					type="number"
					min="1"
					bind:value={share}
				/>
			</label>
			<Button type="submit" disabled={busy}
				>{busy ? 'Reading…' : 'Show what I would approve'}</Button
			>
		</form>
		<p class="mt-2 text-xs text-muted-foreground">
			Reading pulls the image (or prebuilds it), which can take a while. Nothing changes until you
			approve.
		</p>
		{#if error}
			<p class="mt-3 rounded-md border px-3 py-2 text-sm">{error}</p>
		{/if}
		{#if applied}
			<p class="mt-3 rounded-md border px-3 py-2 text-sm">{applied.message}</p>
			{#each applied.notes as n (n)}
				<p class="mt-1 text-sm text-muted-foreground">{n}</p>
			{/each}
		{/if}
	</CardSection>
	{#if preview}
		<CardSection class="border-t pt-4">
			<h3 class="text-lg font-semibold">
				{preview.name} <span class="font-normal text-muted-foreground">({preview.id})</span>
			</h3>
			<p class="text-sm text-muted-foreground">github:{preview.repo}</p>
			<p class="mt-2 text-sm">{preview.description}</p>
			<div class="mt-2 flex flex-wrap gap-1.5">
				{#each preview.kinds as k (k)}<Badge variant="secondary">{k}</Badge>{/each}
				<Badge variant="outline"
					>{preview.listed
						? 'key matches the signed directory'
						: 'not in the directory: compare the key yourself'}</Badge
				>
			</div>
			<p class="mt-2 font-mono text-xs break-all text-muted-foreground">key {preview.key}</p>
			{#each preview.devcontainer_notes as n (n)}
				<p class="mt-1 text-sm text-muted-foreground">note: {n}</p>
			{/each}
			<h4 class="mt-4 font-medium">What you are approving</h4>
			<div class="mt-2"><Approval approval={preview.approval} /></div>
			{#each preview.notes as n (n)}
				<p class="mt-2 text-sm">{n}</p>
			{/each}
			<div class="mt-4 flex gap-3">
				<Button onclick={approve} disabled={busy}
					>Support this project and approve this environment and agent</Button
				>
				<Button variant="outline" onclick={() => (preview = null)}>Cancel</Button>
			</div>
		</CardSection>
	{/if}
</Card>

<h2 class="mt-8 text-lg font-semibold">Supported</h2>
{#if projects.length === 0}
	<p class="mt-2 text-sm text-muted-foreground">None yet.</p>
{:else}
	<div class="mt-3 grid gap-4 sm:grid-cols-2">
		{#each projects as p (p.id)}
			<Card>
				<CardSection>
					<a
						href={resolve('/projects/[id]', { id: p.id })}
						class="text-lg font-semibold hover:underline">{p.id}</a
					>
					<p class="text-sm text-muted-foreground">
						{p.source ? `github:${p.source}` : 'added by hand'} · share {p.share}
					</p>
					{#if p.approval}
						<div class="mt-2 flex flex-wrap gap-1.5">
							<Badge variant="outline">{p.approval.short}</Badge>
							<Badge variant="secondary">{p.approval.harness}</Badge>
							{#if p.approval.needs_network}<Badge variant="outline">network</Badge>{/if}
						</div>
					{:else}
						<p class="mt-2 text-sm text-muted-foreground">no approved environment</p>
					{/if}
				</CardSection>
			</Card>
		{/each}
	</div>
{/if}
