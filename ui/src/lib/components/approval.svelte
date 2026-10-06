<script lang="ts">
	import { Badge } from '#lib/components/ui/index.js';
	import { harnessLabel, type Approval } from '#lib/api.js';

	let { approval: a }: { approval: Approval } = $props();
</script>

<div class="flex flex-wrap gap-1.5">
	<Badge variant="outline">{harnessLabel(a.harness)}</Badge>
	{#if a.model}<Badge variant="secondary">{a.model}</Badge>{/if}
	{#if a.needs_network}<Badge variant="outline">needs a network</Badge>{/if}
	{#if a.nested_sandbox}<Badge variant="outline">nested sandbox</Badge>{/if}
	{#if a.prebuilt}<Badge variant="outline">prebuilt here</Badge>{/if}
</div>
<dl class="mt-3 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[8rem_1fr]">
	<dt class="text-muted-foreground">image</dt>
	<dd class="font-mono text-xs break-all">{a.pinned}</dd>
	<dt class="text-muted-foreground">commit</dt>
	<dd class="font-mono text-xs">{a.commit ?? 'unknown'}</dd>
	<dt class="text-muted-foreground">agent hash</dt>
	<dd class="font-mono text-xs">{a.agent_hash.slice(0, 16)}…</dd>
	{#if a.skills.length}
		<dt class="text-muted-foreground">skills</dt>
		<dd>{a.skills.join(', ')}</dd>
	{/if}
	{#if a.mcp.length}
		<dt class="text-muted-foreground">MCP servers</dt>
		<dd>
			{#each a.mcp as [name, how] (name)}
				<div>
					<span class="font-medium">{name}</span> <span class="text-muted-foreground">{how}</span>
				</div>
			{/each}
		</dd>
	{/if}
	{#if a.egress_rules.length}
		<dt class="text-muted-foreground">egress rules</dt>
		<dd class="font-mono text-xs whitespace-pre-line">{a.egress_rules.join('\n')}</dd>
	{/if}
</dl>
<details class="mt-3 text-sm">
	<summary class="cursor-pointer text-muted-foreground">Everything shown at approval</summary>
	<pre class="mt-2 overflow-x-auto rounded-md bg-muted p-3 text-xs">{a.describe.join('\n')}</pre>
</details>
