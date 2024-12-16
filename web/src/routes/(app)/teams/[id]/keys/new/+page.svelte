<script lang="ts">
import { goto } from "$app/navigation";
import { page } from "$app/stores";
import { getCurrentUser } from "$lib/currentUser.svelte";
import { KeycastApi } from "$lib/keycast_api.svelte";
import ndk from "$lib/ndk.svelte";
import type { StoredKey } from "$lib/types";
import { type NDKEvent, NDKNip07Signer } from "@nostr-dev-kit/ndk";
import { toast } from "svelte-hot-french-toast";

const { id } = $page.params;

const api = new KeycastApi();
const user = $derived(getCurrentUser()?.user);

let unsignedAuthEvent: NDKEvent | null = $state(null);
let secretKey: string = $state("");
let encryptedSecretKey: string = $state("");
let password: string = $state("");
let keyName: string = $state("");
let keyError: string | null = $state(null);

async function createKey() {
    if (!user?.pubkey) return;
    if ((!secretKey && !password) || !encryptedSecretKey) {
        keyError =
            "You must provide either an encrypted secret key or a private key and password.";
        return;
    }
    if (!keyName) {
        keyError = "You must provide a key name.";
        return;
    }

    api.buildUnsignedAuthEvent(
        `/teams/${id}/keys`,
        "POST",
        user.pubkey,
        JSON.stringify({
            key_name: keyName,
            encrypted_secret_key: encryptedSecretKey,
        }),
    ).then(async (event) => {
        unsignedAuthEvent = event;
        if (unsignedAuthEvent) {
            if (!ndk.signer) {
                ndk.signer = new NDKNip07Signer();
            }
            await unsignedAuthEvent.sign();
            const encodedAuthEvent = `Nostr ${btoa(JSON.stringify(unsignedAuthEvent))}`;
            api.post<StoredKey>(`/teams/${id}/keys`, {
                headers: { Authorization: encodedAuthEvent },
            })
                .then((newKey) => {
                    toast.success("Key created successfully");
                    goto(`/teams/${id}`);
                })
                .catch((error) => {
                    toast.error("Failed to create key");
                    keyError = error.message;
                });
        }
    });
}
</script>

<h1 class="page-header">Create Key</h1>

<form onsubmit={() => createKey()}>
    <div class="form-group">
  <label for="keyName">Key Name</label>
        <input type="text" bind:value={keyName} />
    </div>
    <div class="form-group">
        <label for="encryptedSecretKey">Encrypted secret key (starting with "ncryptsec1&hellip;")</label>
        <input type="text" placeholder="ncryptsec1..." bind:value={encryptedSecretKey} />
    </div>

    <div class="form-group text-sm text-gray-400 w-full md:w-1/2 flex flex-col gap-2">
        <span>Or, if you don't have an encrypted secret key already, we can create one for you using your private key and a password.</span>
        <span>Keycast doesn't store your nsec, only the encrypted secret key. Which means you must store this password in a secure location in order to decrypt the key later. Your nsec will continue to work as normal anywhere else you use it.</span>
    </div>
    
    <div class="form-group">
        <label for="secretKey">Private key (nsec or hex)</label>
        <input type="password" placeholder="nsec1..." bind:value={secretKey} />
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" bind:value={password} />
    </div>
    <button type="submit" class="button button-primary">Securely Store Key</button>
</form>
