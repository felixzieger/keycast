import ndk from "$lib/ndk.svelte";
import type { NDKUser } from "@nostr-dev-kit/ndk";

export function truncatedNpubForPubkey(pubkey?: string, maxLength = 9) {
    return ndk.getUser({ pubkey: pubkey })?.npub.slice(0, maxLength);
}

export function userFromPubkeyOrNpub(pubkeyOrNpub: string): NDKUser | null {
    if (pubkeyOrNpub.startsWith("npub1")) {
        return ndk.getUser({ npub: pubkeyOrNpub });
    }
    return ndk.getUser({ pubkey: pubkeyOrNpub });
}
