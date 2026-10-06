<script lang="ts">
	import './layout.css';
	import favicon from '#lib/assets/favicon.svg';
	import { resolve } from '$app/paths';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();
	const repo = 'https://github.com/jvanbuel/toto';
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<div class="mx-auto flex min-h-screen max-w-5xl flex-col px-4 sm:px-6">
	<header class="flex items-center justify-between py-5">
		<a href={resolve('/')} class="flex items-center gap-2 text-lg font-semibold tracking-tight"
			><img src={favicon} alt="" class="h-6 w-6" /> toto</a
		>
		<nav class="flex gap-5 text-sm text-muted-foreground">
			<a href="{resolve('/')}#projects" class="hover:text-foreground">Projects</a>
			<a href="{resolve('/')}#contribute" class="hover:text-foreground">Contribute</a>
			<a href="{repo}/blob/main/docs/project-owner-guide.md" class="hover:text-foreground"
				>Run a project</a
			>
			<a href={repo} class="hover:text-foreground">GitHub</a>
		</nav>
	</header>
	<main class="flex-1 pb-16">
		{@render children()}
	</main>
	<footer class="border-t py-6 text-sm text-muted-foreground">
		toto — Tokens Offered To Others. Your credentials never leave your machine.
		<a href="{repo}/blob/main/directory/README.md" class="underline underline-offset-4"
			>How projects get listed.</a
		>
	</footer>
</div>
