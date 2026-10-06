<script lang="ts">
	import type { HTMLAnchorAttributes, HTMLButtonAttributes } from 'svelte/elements';
	import { cn } from '#lib/utils.js';

	type Variant = 'default' | 'secondary' | 'outline' | 'ghost' | 'link';
	type Size = 'default' | 'sm' | 'lg';
	type Props = (HTMLButtonAttributes & HTMLAnchorAttributes) & {
		variant?: Variant;
		size?: Size;
		href?: string;
	};

	let {
		class: className,
		variant = 'default',
		size = 'default',
		href,
		children,
		...rest
	}: Props = $props();

	const variants: Record<Variant, string> = {
		default: 'bg-primary text-primary-foreground shadow-xs hover:bg-primary/90',
		secondary: 'bg-secondary text-secondary-foreground shadow-xs hover:bg-secondary/80',
		outline: 'border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground',
		ghost: 'hover:bg-accent hover:text-accent-foreground',
		link: 'text-primary underline-offset-4 hover:underline'
	};
	const sizes: Record<Size, string> = {
		default: 'h-9 px-4 py-2',
		sm: 'h-8 rounded-md px-3 text-xs',
		lg: 'h-10 rounded-md px-6'
	};
	const classes = $derived(
		cn(
			'inline-flex shrink-0 items-center justify-center gap-2 rounded-md text-sm font-medium whitespace-nowrap transition-all outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50',
			variants[variant],
			sizes[size],
			className
		)
	);
</script>

{#if href}
	<a {href} class={classes} {...rest}>{@render children?.()}</a>
{:else}
	<button class={classes} {...rest}>{@render children?.()}</button>
{/if}
