export const load = async ({ cookies }) => {
    const keycastCookie = cookies.get("keycastUserPubkey");
    return { keycastCookie };
};
