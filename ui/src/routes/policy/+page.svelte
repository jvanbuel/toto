<script lang="ts">
	import { onMount } from 'svelte';
	import { Button, Card, CardSection } from '#lib/components/ui/index.js';
	import { get, put, type Policy } from '#lib/api.js';

	let policy = $state<Policy | null>(null);
	let error = $state('');
	let saved = $state(false);
	let quiet = $state(false);
	let quietStart = $state(22);
	let quietEnd = $state(7);

	onMount(async () => {
		try {
			policy = await get<Policy>('/policy');
			quiet = policy.quiet_hours !== null;
			if (policy.quiet_hours) [quietStart, quietEnd] = policy.quiet_hours;
		} catch (e) {
			error = (e as Error).message;
		}
	});

	async function save() {
		if (!policy) return;
		error = '';
		saved = false;
		try {
			policy = await put<Policy>('/policy', {
				...policy,
				quiet_hours: quiet ? [quietStart, quietEnd] : null
			});
			saved = true;
		} catch (e) {
			error = (e as Error).message;
		}
	}
</script>

<h1 class="text-2xl font-semibold tracking-tight">Policy</h1>
<p class="mt-1 text-sm text-muted-foreground">
	What you give, and what you keep. Per-task limits and allowed kinds stay in the config file.
</p>

{#if policy}
	<form
		class="mt-6"
		onsubmit={(e) => {
			e.preventDefault();
			save();
		}}
	>
		<Card>
			<CardSection class="grid gap-5 sm:grid-cols-2">
				<label class="flex flex-col gap-1 text-sm">
					<span class="font-medium">Daily token cap</span>
					<input
						class="h-9 rounded-md border bg-background px-3"
						type="number"
						min="0"
						step="1000"
						bind:value={policy.daily_token_cap}
					/>
					<span class="text-xs text-muted-foreground"
						>Tokens donated per local day, across all projects.</span
					>
				</label>
				<label class="flex flex-col gap-1 text-sm">
					<span class="font-medium">Reserve</span>
					<input
						class="h-9 rounded-md border bg-background px-3"
						type="number"
						min="0"
						max="100"
						bind:value={policy.reserve_pct}
					/>
					<span class="text-xs text-muted-foreground"
						>Percent of each provider window kept for you; tasks pause below it.</span
					>
				</label>
				<div class="flex flex-col gap-2 text-sm sm:col-span-2">
					<label class="flex items-center gap-2 font-medium"
						><input type="checkbox" bind:checked={quiet} /> Quiet hours</label
					>
					{#if quiet}
						<div class="flex items-center gap-2">
							from <input
								class="h-9 w-16 rounded-md border bg-background px-2"
								type="number"
								min="0"
								max="23"
								bind:value={quietStart}
							/>
							to
							<input
								class="h-9 w-16 rounded-md border bg-background px-2"
								type="number"
								min="0"
								max="23"
								bind:value={quietEnd}
							/>
							<span class="text-xs text-muted-foreground"
								>local hours; no tasks are taken in between (may wrap midnight)</span
							>
						</div>
					{/if}
				</div>
			</CardSection>
			{#if Object.keys(policy.project_shares).length}
				<CardSection class="border-t pt-4">
					<p class="text-sm font-medium">Shares</p>
					<p class="text-xs text-muted-foreground">
						Relative weights: a project with share 2 gets twice the tasks of one with share 1.
					</p>
					<div class="mt-2 grid gap-2 sm:grid-cols-2">
						{#each Object.keys(policy.project_shares) as id (id)}
							<label class="flex items-center justify-between gap-3 text-sm">
								<span>{id}</span>
								<input
									class="h-9 w-20 rounded-md border bg-background px-2"
									type="number"
									min="1"
									bind:value={policy.project_shares[id]}
								/>
							</label>
						{/each}
					</div>
				</CardSection>
			{/if}
			<CardSection class="flex items-center gap-3 border-t pt-4">
				<Button type="submit">Save</Button>
				{#if saved}<span class="text-sm text-muted-foreground"
						>saved; restart the daemon to apply</span
					>{/if}
				{#if error}<span class="text-sm">{error}</span>{/if}
			</CardSection>
		</Card>
	</form>
{:else if error}
	<p class="mt-3 rounded-md border px-3 py-2 text-sm">{error}</p>
{:else}
	<p class="mt-3 text-sm text-muted-foreground">Loading…</p>
{/if}
