<script lang="ts">
	import './layout.css';
	import favicon from '#lib/assets/favicon.svg';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { token } from '#lib/api.js';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();
	const hasToken = $derived(token() !== '');
	const links = [
		{ href: resolve('/'), label: 'Overview' },
		{ href: resolve('/projects'), label: 'Projects' },
		{ href: resolve('/policy'), label: 'Policy' }
	];
	const active = (href: string) =>
		href === '/' ? page.url.pathname === '/' : page.url.pathname.startsWith(href);
</script>

<svelte:head>
	<title>toto</title>
	<link rel="icon" href={favicon} />
</svelte:head>

<div class="mx-auto flex min-h-screen max-w-4xl flex-col px-4 sm:px-6">
	<header class="flex items-center justify-between py-5">
		<a href={resolve('/')} class="flex items-center gap-2 text-lg font-semibold tracking-tight"
			><img src={favicon} alt="" class="h-6 w-6" /> toto</a
		>
		<nav class="flex gap-5 text-sm">
			{#each links as l (l.href)}
				<a
					href={l.href}
					class={active(l.href) ? 'font-medium' : 'text-muted-foreground hover:text-foreground'}
					>{l.label}</a
				>
			{/each}
		</nav>
	</header>
	<main class="flex-1 pb-16">
		{#if !hasToken}
			<p class="rounded-md border px-4 py-3 text-sm">
				No session token. Open the URL that <code>toto ui</code> printed, which carries it.
			</p>
		{:else}
			{@render children()}
		{/if}
	</main>
	<footer class="border-t py-5 text-xs text-muted-foreground">
		This page talks to the runner on this machine only. Changes to projects and policy take effect
		before the runner's next task; a running task finishes as it started.
	</footer>
</div>
