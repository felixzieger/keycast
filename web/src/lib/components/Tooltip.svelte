<script lang="ts"> 
import tippy from "tippy.js";
import 'tippy.js/dist/tippy.css';
import { Info } from "phosphor-svelte";

let { content = $bindable(), size = 20 }: { content: string, size: number } = $props();

let tooltip: Element | null = $state(null);

$effect(() => {
    if (!tooltip) return;
    tippy(tooltip, { content });
});
</script>

<span bind:this={tooltip}>
    <Info {size} />
</span>
