export type StoredKey = {
    id: number;
    name: string;
    team_id: number;
    public_key: string;
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
    policy_id: number;
    max_uses: number;
    expires_at: Date;
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
    team_users: User[];
    stored_keys: StoredKey[];
    policies: PolicyWithPermissions[];
};

export type KeyWithRelations = {
    team: Team;
    stored_key: StoredKey;
    authorizations: AuthorizationWithRelations[];
};

export type TeamWithKey = {
    team: Team;
    stored_key: StoredKey;
};

export type Policy = {
    id: number;
    name: string;
    team_id: number;
    created_at: Date;
    updated_at: Date;
};

export type AuthorizationWithPolicy = {
    authorization: Authorization;
    policy: Policy;
};

export type AuthorizationWithRelations = {
    authorization: Authorization;
    policy: Policy;
    users: User[];
    connection_string: string;
};

export type Permission = {
    identifier: string;
    config: JsonValue;
    created_at: Date;
    updated_at: Date;
};

export type PolicyWithPermissions = {
    policy: Policy;
    permissions: Permission[];
};

export const AVAILABLE_PERMISSIONS = [
    "allowed_kinds",
    "content_filter",
    "encrypt_to_self",
];

export type JsonValue =
    | string
    | number
    | boolean
    | null
    | JsonValue[]
    | { [key: string]: JsonValue };

export type AllowedKindsConfig = {
    sign: number[] | null;
    encrypt: number[] | null;
    decrypt: number[] | null;
};

export type ContentFilterConfig = {
    blocked_words: string[] | null;
};
