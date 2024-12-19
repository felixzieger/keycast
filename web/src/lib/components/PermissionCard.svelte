<script lang="ts">
import type { Permission } from "$lib/types";
import { readablePermissionConfig } from "$lib/utils/permissions";
import { toTitleCase } from "$lib/utils/strings";

let { permission }: { permission: Permission } = $props();
</script>

<div class="card">
    <h3 class="text-xl font-bold">{toTitleCase(permission.identifier)}</h3>
    {#each readablePermissionConfig(permission) as config}
        <div class="text-xs text-gray-400">{config}</div>
    {/each}
</div>
