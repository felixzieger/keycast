export type StoredKey = {
    id: number;
    name: string;
    public_key: string;
    encrypted_secret_key: string;
    created_at: Date;
    updated_at: Date;
};

export type User = {
    user_public_key: string;
    role: "Admin" | "Member";
    created_at: Date;
    updated_at: Date;
};

export type Authorization = {
    id: number;
    stored_key_id: number;
    secret: string;
    bunker_nsec: string;
    relays: string[];
    policy: Policy;
    created_at: Date;
    updated_at: Date;
};

export type Team = {
    id: number;
    name: string;
    created_at: Date;
    updated_at: Date;
};

export type TeamWithRelations = {
    team: Team;
    users: User[];
    stored_keys: StoredKey[];
};

export type Policy = {
    max_uses: number;
    expires_at?: Date;
    get_pubkey: boolean;
    sign_kinds?: number[];
    nip04encrypt: boolean;
    nip04decrypt: boolean;
    nip44encrypt: boolean;
    nip44decrypt: boolean;
};
