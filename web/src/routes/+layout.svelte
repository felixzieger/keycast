<script lang="ts">
	import '../app.css';
	import Header from '$lib/components/Header.svelte';
	import { getCurrentUser, setCurrentUser } from "$lib/currentUser.svelte";
	import { initApi } from '$lib/keycast_api.svelte';
	import ndk from "$lib/ndk.svelte";
	import { SigninMethod, signin, signout } from "$lib/utils/auth";
	import { onMount } from "svelte";
	import { Toaster } from "svelte-hot-french-toast";

	let { data, children } = $props();
	let keycastCookie = $derived(data.keycastCookie);
	initApi();

	$effect(() => {
		if (keycastCookie && getCurrentUser()?.user?.pubkey !== keycastCookie) {
			setCurrentUser(keycastCookie);
		}
	});

	onMount(() => {
		if (!window.nostr) {
			import("nostr-login")
				.then(async ({ init }) => {
					init({
						onAuth(npub, options) {
							if (options.type === "logout") {
								signout(ndk);
							} else {
								let user = ndk.getUser({ npub });
								signin(ndk, undefined, SigninMethod.NostrLogin, undefined, user);
							}
						},
					});
				})
				.catch((error) => console.log("Failed to load nostr-login", error));
		}
	});

</script>

<Toaster />
<Header />

<div class="container">
	{@render children()}
</div>


