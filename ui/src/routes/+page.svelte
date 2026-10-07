<script lang="ts">
	import { onMount } from 'svelte';
	import { Badge, Button, Card, CardSection } from '#lib/components/ui/index.js';
	import { fmt, get, post, watchStatus, type Overview, type Status } from '#lib/api.js';

	let data = $state<Overview | null>(null);
	let error = $state('');

	async function refresh() {
		try {
			data = await get<Overview>('/overview');
			error = '';
		} catch (e) {
			error = (e as Error).message;
		}
	}
	onMount(() => {
		refresh();
		const t = setInterval(refresh, 15000);
		const stop = watchStatus((s) => {
			if (data) data.status = s;
		});
		return () => {
			clearInterval(t);
			stop();
		};
	});

	let toggling = $state(false);
	async function toggle() {
		if (!data) return;
		toggling = true;
		try {
			const s = await post<Status>(data.status?.user_paused ? '/resume' : '/pause');
			data.status = s;
		} catch (e) {
			error = (e as Error).message;
		} finally {
			toggling = false;
		}
	}

	const runnerState = $derived(data?.status?.state ?? 'not running');
	const pct = $derived(
		data && data.daily_token_cap > 0
			? Math.min(100, Math.round((data.used_today / data.daily_token_cap) * 100))
			: 0
	);
	const when = (iso: string) =>
		new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
</script>

{#if error}
	<p class="rounded-md border px-4 py-3 text-sm">{error}</p>
{:else if data}
	<div class="grid gap-4 sm:grid-cols-3">
		<Card>
			<CardSection>
				<p class="text-sm text-muted-foreground">Runner</p>
				<p class="mt-1 text-2xl font-semibold capitalize">{runnerState}</p>
				{#if data.status?.task}
					<p class="mt-1 text-sm text-muted-foreground">last task {data.status.task}</p>
				{/if}
				<div class="mt-3">
					<Button
						size="sm"
						variant={data.status?.user_paused ? 'default' : 'outline'}
						onclick={toggle}
						disabled={toggling}
					>
						{data.status?.user_paused ? 'Resume' : 'Pause'}
					</Button>
				</div>
				{#if data.status}
					<p class="mt-1 text-xs text-muted-foreground">
						{data.status.submitted} submitted, {data.status.dropped} dropped, updated {when(
							data.status.updated
						)}
					</p>
				{:else}
					<p class="mt-1 text-xs text-muted-foreground">
						no status file yet: start with `toto run`
					</p>
				{/if}
			</CardSection>
		</Card>
		<Card>
			<CardSection>
				<p class="text-sm text-muted-foreground">Today</p>
				<p class="mt-1 text-2xl font-semibold">{fmt(data.used_today)}</p>
				<p class="mt-1 text-sm text-muted-foreground">
					of {fmt(data.daily_token_cap)} tokens ({pct}%)
				</p>
				<div class="mt-2 h-1.5 w-full rounded bg-muted">
					<div class="h-1.5 rounded bg-primary" style="width: {pct}%"></div>
				</div>
			</CardSection>
		</Card>
		<Card>
			<CardSection>
				<p class="text-sm text-muted-foreground">Reserve</p>
				<p class="mt-1 text-2xl font-semibold">{data.reserve_pct}%</p>
				<p class="mt-1 text-sm text-muted-foreground">
					of each provider window kept for you; {data.projects}
					{data.projects === 1 ? 'project' : 'projects'} supported
				</p>
			</CardSection>
		</Card>
	</div>

	{#if data.status?.user_paused}
		<Card class="mt-4">
			<CardSection>
				<p class="font-medium">Paused by you</p>
				<p class="text-sm text-muted-foreground">
					No new task is taken until you resume; a task that was running finishes first.
				</p>
			</CardSection>
		</Card>
	{:else if data.status?.state === 'paused'}
		<Card class="mt-4">
			<CardSection>
				<p class="font-medium">Paused: {data.status.pause_reason}</p>
				<p class="text-sm text-muted-foreground">
					until {data.status.paused_until ? when(data.status.paused_until) : 'the next check'}; the
					next task refreshes the provider's figures.
				</p>
			</CardSection>
		</Card>
	{/if}
	{#if data.status?.config_error}
		<Card class="mt-4">
			<CardSection>
				<p class="font-medium">Your latest config edit was not applied</p>
				<p class="text-sm text-muted-foreground">{data.status.config_error}</p>
			</CardSection>
		</Card>
	{/if}
	{#if data.status?.last_error}
		<Card class="mt-4">
			<CardSection>
				<p class="font-medium">Last error</p>
				<p class="text-sm text-muted-foreground">{data.status.last_error}</p>
			</CardSection>
		</Card>
	{/if}

	<h2 class="mt-8 text-lg font-semibold">Audit log</h2>
	<p class="text-sm text-muted-foreground">The last {data.audit.length} entries, newest first.</p>
	{#if data.audit.length === 0}
		<p class="mt-3 text-sm text-muted-foreground">Nothing yet.</p>
	{:else}
		<div class="mt-3 overflow-x-auto rounded-md border">
			<table class="w-full text-sm">
				<thead class="bg-muted/50 text-left text-xs text-muted-foreground">
					<tr>
						<th class="px-3 py-2 font-medium">When</th>
						<th class="px-3 py-2 font-medium">Task</th>
						<th class="px-3 py-2 font-medium">Project</th>
						<th class="px-3 py-2 font-medium">Outcome</th>
						<th class="px-3 py-2 text-right font-medium">Tokens</th>
						<th class="px-3 py-2 font-medium">Detail</th>
					</tr>
				</thead>
				<tbody>
					{#each data.audit as e (e.ts + e.task_id + e.outcome)}
						<tr class="border-t">
							<td class="px-3 py-2 whitespace-nowrap">{new Date(e.ts).toLocaleString()}</td>
							<td class="px-3 py-2 font-mono text-xs">{e.task_id}</td>
							<td class="px-3 py-2">{e.project_id}</td>
							<td class="px-3 py-2"
								><Badge variant={e.outcome === 'submitted' ? 'default' : 'secondary'}
									>{e.outcome}</Badge
								></td
							>
							<td class="px-3 py-2 text-right">{fmt(e.tokens)}</td>
							<td class="max-w-md truncate px-3 py-2 text-muted-foreground" title={e.detail}
								>{e.detail}</td
							>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
	<p class="mt-6 text-xs text-muted-foreground">config {data.config_path}</p>
{:else}
	<p class="text-sm text-muted-foreground">Loading…</p>
{/if}
