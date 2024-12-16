<script lang="ts">
    import { SpinnerBall } from "phosphor-svelte";

    let { extraClasses }: { extraClasses?: string } = $props();
</script>

<div class="flex flex-row items-center gap-2 {extraClasses}">
    <SpinnerBall size="24" weight="light" class="animate-spin" />
    Loading...
</div>
