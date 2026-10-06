<script lang="ts">
	import type { HTMLAttributes } from 'svelte/elements';
	import { cn } from '#lib/utils.js';

	let { class: className, children, ...rest }: HTMLAttributes<HTMLDivElement> = $props();
</script>

<div class={cn('px-5', className)} {...rest}>
	{@render children?.()}
</div>
