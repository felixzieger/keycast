<script lang="ts">
import { page } from "$app/stores";
import PageSection from "$lib/components/PageSection.svelte";
import { getCurrentUser } from "$lib/currentUser.svelte";
import { KeycastApi } from "$lib/keycast_api.svelte";
import ndk from "$lib/ndk.svelte";
import type {
    Permission,
    Policy,
    StoredKey,
    Team,
    TeamWithRelations,
} from "$lib/types";
import { type NDKEvent, NDKNip07Signer } from "@nostr-dev-kit/ndk";
import { CaretRight, Plus, X } from "phosphor-svelte";
import { toast } from "svelte-hot-french-toast";

const { id } = $page.params;

const api = new KeycastApi();
const user = $derived(getCurrentUser()?.user);
let isLoading = $state(true);
let unsignedAuthEvent: NDKEvent | null = $state(null);
let encodedAuthEvent: string | null = $state(null);

let policyName: string = $state("");
let permissions: Permission[] = $state([]);

let teamWithRelations: TeamWithRelations | null = $state(null);
let team: Team | null = $state(null);
let policies: Policy[] = $state([]);

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
                            team = teamWithRelations.team;
                            policies = teamWithRelations.policies;
                        })
                        .finally(() => {
                            isLoading = false;
                        });
                }
            },
        );
    }
});

async function createPolicy() {}

async function addPermission() {}
</script>
    
<h1 class="page-header flex flex-row gap-1 items-center">
    <a href={`/teams/${id}`} class="bordered">{team?.name}</a>
    <CaretRight size="20" class="text-gray-500" />
    Add Policy
</h1>
    