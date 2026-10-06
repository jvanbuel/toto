<script lang="ts">
	import { resolve } from '$app/paths';
	import { Badge, Button, Card, CardSection } from '#lib/components/ui/index.js';
	import { harnessLabel } from '#lib/directory.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const p = $derived(data.project);
	const repoUrl = $derived(`https://github.com/${p.repo}`);
</script>

<svelte:head>
	<title>{p.name} — toto</title>
	<meta name="description" content={p.description} />
</svelte:head>

<a href="{resolve('/')}#projects" class="text-sm text-muted-foreground hover:text-foreground"
	>← all projects</a
>

<h1 class="mt-4 text-3xl font-semibold tracking-tight">{p.name}</h1>
<p class="mt-1 text-muted-foreground">
	<a href={repoUrl} class="hover:underline">github:{p.repo}</a> · listed {p.added || 'unknown'}
</p>
<p class="mt-5 max-w-2xl text-lg">{p.description}</p>

<div class="mt-8 grid gap-4 sm:grid-cols-2">
	<Card>
		<CardSection>
			<h2 class="font-semibold">What its tasks need</h2>
			<dl class="mt-3 space-y-2 text-sm">
				<div class="flex justify-between gap-4">
					<dt class="text-muted-foreground">Credential</dt>
					<dd>{harnessLabel(p.harness)}</dd>
				</div>
				<div class="flex justify-between gap-4">
					<dt class="text-muted-foreground">Network</dt>
					<dd>
						{p.needs_network
							? 'yes, through your fenced network, with the egress rules in its agent config'
							: 'none'}
					</dd>
				</div>
				<div class="flex justify-between gap-4">
					<dt class="text-muted-foreground">Task kinds</dt>
					<dd class="flex flex-wrap justify-end gap-1">
						{#each p.kinds as k (k)}
							<Badge variant="secondary">{k}</Badge>
						{/each}
					</dd>
				</div>
			</dl>
		</CardSection>
	</Card>
	<Card>
		<CardSection>
			<h2 class="font-semibold">Support it</h2>
			<code class="mt-3 block rounded-md bg-muted px-3 py-2 text-sm">toto projects add {p.id}</code>
			<p class="mt-3 text-sm text-muted-foreground">
				Your runner reads the project's files at their current commit, pulls its image, shows you
				both and asks once. The key below is what the directory lists; your runner refuses the
				project if its repository publishes a different one.
			</p>
		</CardSection>
	</Card>
</div>

<Card class="mt-4">
	<CardSection>
		<h2 class="font-semibold">What you would approve</h2>
		<ul class="mt-3 space-y-1 text-sm">
			<li>
				<a
					href="{repoUrl}/blob/main/.devcontainer/devcontainer.json"
					class="underline underline-offset-4">.devcontainer/devcontainer.json</a
				>
				<span class="text-muted-foreground">
					— the environment, with toto's block under customizations.toto</span
				>
			</li>
			<li>
				<a href="{repoUrl}/tree/main/.toto/agent" class="underline underline-offset-4"
					>.toto/agent</a
				>
				<span class="text-muted-foreground">
					— the Omnigent agent: prompt, MCP servers, skills, egress rules</span
				>
			</li>
		</ul>
		<p class="mt-4 font-mono text-xs break-all text-muted-foreground">key {p.public_key}</p>
	</CardSection>
</Card>

<div class="mt-6">
	<Button variant="outline" href={repoUrl}>Repository</Button>
</div>
