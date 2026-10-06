<script lang="ts">
	import { resolve } from '$app/paths';
	import { Badge, Button, Card, CardSection } from '#lib/components/ui/index.js';
	import { harnessLabel } from '#lib/directory.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const docs = 'https://github.com/jvanbuel/toto/blob/main';
</script>

<svelte:head>
	<title>toto — donate unused AI capacity to projects you choose</title>
	<meta
		name="description"
		content="toto runs a project's own agent in the project's own dev container on your machine, on your subscription, with your credentials never leaving it."
	/>
</svelte:head>

<section class="py-10 sm:py-16">
	<h1 class="max-w-3xl text-4xl font-semibold tracking-tight sm:text-5xl">
		Donate the AI capacity you are not using.
	</h1>
	<p class="mt-5 max-w-2xl text-lg text-muted-foreground">
		toto is a small daemon that runs tasks for projects you choose, in each project's own dev
		container on your machine, on your own subscription or API key. The credential stays in a proxy
		on your host. You set a daily cap and a reserve for yourself; the runner pauses when your
		provider says you are close to it.
	</p>
	<div class="mt-7 flex flex-wrap gap-3">
		<Button href="#contribute">Start contributing</Button>
		<Button variant="outline" href="{docs}/docs/project-owner-guide.md"
			>Run a project on toto</Button
		>
	</div>
</section>

<section id="projects" class="scroll-mt-6 py-8">
	<div class="flex items-baseline justify-between">
		<h2 class="text-2xl font-semibold tracking-tight">Projects</h2>
		<p class="text-sm text-muted-foreground">
			{data.projects.length}
			{data.projects.length === 1 ? 'project' : 'projects'}, directory signed {data.updated ||
				'unknown'}
		</p>
	</div>
	<p class="mt-2 max-w-2xl text-sm text-muted-foreground">
		Every project here is in the signed directory your runner verifies. Adding one shows you its
		image and its agent before anything runs, and your runner starts exactly what you approved.
	</p>
	{#if data.projects.length === 0}
		<Card class="mt-6">
			<CardSection>
				<p class="font-medium">No projects listed yet.</p>
				<p class="mt-1 text-sm text-muted-foreground">
					The directory is empty until the maintainers list the first project. Projects that want
					in:
					<a href="{docs}/docs/project-owner-guide.md" class="underline underline-offset-4"
						>the owner guide</a
					> says what to publish.
				</p>
			</CardSection>
		</Card>
	{:else}
		<div class="mt-6 grid gap-4 sm:grid-cols-2">
			{#each data.projects as p (p.id)}
				<Card>
					<CardSection class="flex items-start justify-between gap-3">
						<div>
							<a
								href={resolve('/projects/[id]', { id: p.id })}
								class="text-lg font-semibold hover:underline">{p.name}</a
							>
							<p class="text-sm text-muted-foreground">github:{p.repo}</p>
						</div>
						{#if p.needs_network}
							<Badge variant="outline">needs a network</Badge>
						{/if}
					</CardSection>
					<CardSection>
						<p class="text-sm">{p.description}</p>
					</CardSection>
					<CardSection class="flex flex-wrap gap-1.5">
						{#each p.kinds as k (k)}
							<Badge variant="secondary">{k}</Badge>
						{/each}
						<Badge variant="outline">{harnessLabel(p.harness)}</Badge>
					</CardSection>
					<CardSection>
						<code class="block rounded-md bg-muted px-3 py-2 text-sm">toto projects add {p.id}</code
						>
					</CardSection>
				</Card>
			{/each}
		</div>
	{/if}
</section>

<section id="contribute" class="scroll-mt-6 py-8">
	<h2 class="text-2xl font-semibold tracking-tight">Contribute</h2>
	<div class="prose mt-4 max-w-none prose-zinc dark:prose-invert">
		<p>
			Linux or macOS with Docker, and a Claude subscription, an Anthropic API key or an OpenAI API
			key.
		</p>
		<pre><code
				>cargo install --git https://github.com/jvanbuel/toto
toto init                       # a runner key and a strict starter config
toto login                      # or point api_key_file at a key
toto projects add &lt;name&gt;        # shows the image and the agent; you approve
toto doctor                     # what works, what is missing
toto install-service            # runs in the background from now on</code
			></pre>
		<p>What your runner does with a task:</p>
		<ul>
			<li>
				starts the project's approved image read-only, with no capabilities, as an unprivileged
				user, with no network unless the agent asks and you fenced one;
			</li>
			<li>
				runs the project's own Omnigent agent inside it, with the task's inputs in <code
					>/workspace</code
				>;
			</li>
			<li>
				relays model calls to a proxy on your host that adds your credential and counts tokens; the
				container never holds it;
			</li>
			<li>
				returns only the files the agent changed, signed, and the project opens them as a pull
				request;
			</li>
			<li>
				stops at your daily cap, and pauses when your provider reports less than your reserve left.
			</li>
		</ul>
		<p>
			Everything a project can run is two files in its repository you can read before approving: its
			<code>.devcontainer/devcontainer.json</code> and its agent directory. The
			<a href="{docs}/docs/projects.md">contributor guide</a> has the details, and the
			<a href="{docs}/docs/adr/README.md">decision records</a> the reasons.
		</p>
	</div>
</section>
