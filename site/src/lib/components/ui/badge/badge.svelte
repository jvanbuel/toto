<script lang="ts">
	import type { HTMLAttributes } from 'svelte/elements';
	import { cn } from '#lib/utils.js';

	type Variant = 'default' | 'secondary' | 'outline';
	let {
		class: className,
		variant = 'default',
		children,
		...rest
	}: HTMLAttributes<HTMLSpanElement> & { variant?: Variant } = $props();

	const variants: Record<Variant, string> = {
		default: 'border-transparent bg-primary text-primary-foreground',
		secondary: 'border-transparent bg-secondary text-secondary-foreground',
		outline: 'text-foreground'
	};
</script>

<span
	class={cn(
		'inline-flex w-fit items-center justify-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap',
		variants[variant],
		className
	)}
	{...rest}
>
	{@render children?.()}
</span>
