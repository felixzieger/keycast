<script lang="ts">
import { page } from "$app/stores";
import PageSection from "$lib/components/PageSection.svelte";
import { getCurrentUser } from "$lib/currentUser.svelte";
import { KeycastApi } from "$lib/keycast_api.svelte";
import ndk from "$lib/ndk.svelte";
import type { Policy, StoredKey, Team, TeamWithRelations } from "$lib/types";
import { type NDKEvent, NDKNip07Signer } from "@nostr-dev-kit/ndk";
import { CaretRight, X } from "phosphor-svelte";
import { toast } from "svelte-hot-french-toast";

const { id, pubkey } = $page.params;

const api = new KeycastApi();
const user = $derived(getCurrentUser()?.user);
let isLoading = $state(true);
let unsignedAuthEvent: NDKEvent | null = $state(null);
let encodedAuthEvent: string | null = $state(null);

let maxUses: number = $state(0);
let expiresAt: Date | null = $state(null);
let relaysString: string = $state(
    "wss://relay.nsecbunker.com, wss://relay.nsec.app",
);
let relays: string[] = $derived(
    relaysString.split(",").map((relay) => relay.trim()),
);

let teamWithRelations: TeamWithRelations | null = $state(null);
let team: Team | null = $derived.by(() =>
    teamWithRelations ? teamWithRelations.team : null,
);
let policies: Policy[] = $derived.by(() =>
    teamWithRelations ? teamWithRelations.policies : [],
);
let key: StoredKey | null | undefined = $derived.by(() =>
    teamWithRelations
        ? teamWithRelations.stored_keys.find((key) => key.public_key === pubkey)
        : undefined,
);

$effect(() => {
    if (user?.pubkey && !unsignedAuthEvent) {
        api.buildUnsignedAuthEvent(`/teams/${id}`, "GET", user.pubkey).then(
            async (event) => {
                unsignedAuthEvent = event;
                if (unsignedAuthEvent) {
                    if (!ndk.signer) {
                        ndk.signer = new NDKNip07Signer();
                    }
                    await unsignedAuthEvent.sign();
                    encodedAuthEvent = `Nostr ${btoa(JSON.stringify(unsignedAuthEvent))}`;
                    api.get(`/teams/${id}`, {
                        headers: { Authorization: encodedAuthEvent },
                    })
                        .then((teamResponse) => {
                            teamWithRelations =
                                teamResponse as TeamWithRelations;
                        })
                        .finally(() => {
                            isLoading = false;
                        });
                }
            },
        );
    }
});

async function createAuthorization() {}
</script>

<h1 class="page-header flex flex-row gap-1 items-center">
    <a href={`/teams/${id}`} class="bordered">{team?.name}</a>
    <CaretRight size="20" class="text-gray-500" />
    <a href={`/teams/${id}/keys/${pubkey}`} class="bordered">{key?.name}</a>
    <CaretRight size="20" class="text-gray-500" />
    Add Authorization
</h1>

<PageSection title="Authorization">
    <form onsubmit={() => createAuthorization()}>
        <div class="form-group">
            <label for="maxUses">Maximum uses (Zero for unlimited)</label>
            <input type="number" bind:value={maxUses} />
        </div>

        <div class="form-group">
            <label for="relays">Relays (comma separated)</label>
            <input type="text" bind:value={relaysString} />
        </div>

        <div class="form-group">
            <label for="expiresAt">Expiration date (Leave blank for no expiration)</label>
            <div class="flex flex-row gap-2 items-center">
                <input type="datetime-local" bind:value={expiresAt} />
                {#if expiresAt}
                    <button type="button" class="clear-button" onclick={() => expiresAt = null}>
                        <X weight="light" size={16} />
                    </button>
                {/if}
            </div>
        </div>
    </form>
</PageSection>

    <PageSection title="Policies">
        <div class="flex flex-col gap-4">
            {#if policies.length === 0}
                <p class="text-gray-500">No policies found</p>
            {:else}
                <div class="card-grid">
                    {#each policies as policy}
                        <div class="card">
                            <h3 class="text-lg font-semibold">{policy.name}</h3>
                        </div>
                    {/each}
                </div>
            {/if}
            <button type="button" class="button self-start button-primary !my-0">Add Policy</button>
        </div>
    </PageSection>

    <button type="submit" class="button button-primary">Add Authorization</button>
