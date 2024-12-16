<script lang="ts">
import type { Snippet } from "svelte";

const { title, children }: { title: string; children: Snippet } = $props();
</script>

<div class="my-12">
    <h2 class="page-subheader">{title}</h2>
    {@render children()}
</div>