<script lang="ts">
import { page } from "$app/stores";
import Avatar from "$lib/components/Avatar.svelte";
import Loader from "$lib/components/Loader.svelte";
import Name from "$lib/components/Name.svelte";
import PageSection from "$lib/components/PageSection.svelte";
import { getCurrentUser } from "$lib/currentUser.svelte";
import { KeycastApi } from "$lib/keycast_api.svelte";
import ndk from "$lib/ndk.svelte";
import { type StoredKey, type Team, type TeamWithKey } from "$lib/types";
import { formattedDate } from "$lib/utils/dates";
import {
    type NDKEvent,
    NDKNip07Signer,
    type NDKUser,
    type NDKUserProfile,
} from "@nostr-dev-kit/ndk";
import { CaretRight } from "phosphor-svelte";
import { toast } from "svelte-hot-french-toast";

const { id, pubkey } = $page.params;

const api = new KeycastApi();
const user = $derived(getCurrentUser()?.user);
let isLoading = $state(true);
let unsignedAuthEvent: NDKEvent | null = $state(null);
let encodedAuthEvent: string | null = $state(null);
let team: Team | null = $state(null);
let key: StoredKey | null = $state(null);
let keyUser: NDKUser | null = $state(null);
let keyUserProfile: NDKUserProfile | null = $state(null);

$effect(() => {
    if (user?.pubkey && !unsignedAuthEvent) {
        api.buildUnsignedAuthEvent(
            `/teams/${id}/keys/${pubkey}`,
            "GET",
            user.pubkey,
        ).then(async (event) => {
            unsignedAuthEvent = event;
            if (unsignedAuthEvent) {
                if (!ndk.signer) {
                    ndk.signer = new NDKNip07Signer();
                }
                await unsignedAuthEvent.sign();
                encodedAuthEvent = `Nostr ${btoa(JSON.stringify(unsignedAuthEvent))}`;
                api.get(`/teams/${id}/keys/${pubkey}`, {
                    headers: { Authorization: encodedAuthEvent },
                })
                    .then((teamKeyResponse) => {
                        key = (teamKeyResponse as TeamWithKey).stored_key;
                        team = (teamKeyResponse as TeamWithKey).team;
                    })
                    .finally(() => {
                        isLoading = false;
                    });
            }
        });
    }

    if (key && !keyUser) {
        keyUser = ndk.getUser({ pubkey: key.public_key });
        keyUser.fetchProfile().then((profile) => {
            keyUserProfile = profile;
        });
    }
});

$inspect(key);
</script>

{#if isLoading}
    <Loader extraClasses="items-center justify-center mt-40" />
{:else if team &&key}
    <h1 class="page-header flex flex-row gap-1 items-center"><a href={`/teams/${id}`} class="bordered">{team.name}</a> <CaretRight size="20" class="text-gray-500" /> {key.name}</h1>
    <div
        class="relative"
    >
        <div class="absolute inset-0 bg-cover bg-center bg-gray-800 overflow-hidden rounded-lg">
            {#if keyUserProfile?.banner}
                <img src={keyUserProfile.banner} alt="Banner" class="opacity-20 w-full h-full object-cover object-center rounded-lg" />
            {:else}
                <div class="w-full h-full bg-gray-800"></div>
            {/if}
        </div>
        <div class="relative p-6 flex items-center gap-4">
            <Avatar user={ndk.getUser({ pubkey: key.public_key })} extraClasses="w-24 h-24" />
            <div class="flex flex-col gap-1">
                <span class="font-semibold text-lg">
                    <Name user={ndk.getUser({ pubkey: key.public_key })} />
                </span>
                <span class="text-xs font-mono text-gray-300">
                    {keyUser?.npub}
                </span>
                <span class="text-xs font-mono text-gray-300">
                    {keyUser?.pubkey}
                </span>
                <span class="text-xs font-mono text-gray-400 mt-2">
                    Added: {formattedDate(new Date(key.created_at))}
                </span>
            </div>
        </div>
    </div>


    <PageSection title="Key Authentications">
        <div class="card"></div>
    </PageSection>

    <PageSection title="Danger Zone">
        <button class="button button-danger">Remove key from team</button>
    </PageSection>
{/if}
