use chrono::DateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Authorization {
    pub stored_key_id: u32,
    pub secret: String,
    pub bunker_nsec: String,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
    pub policy: Policy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    /// How many times the authorization can be used
    pub max_uses: u64,
    /// When should the authorization expire? None means never
    pub expires_at: Option<DateTime<chrono::Utc>>,
    /// Should the authorization be able to get the pubkey?
    pub get_pubkey: bool,
    /// What kinds of events should the authorization be able to sign? None means all kinds
    pub sign_kinds: Option<Vec<u64>>,
    /// Should the authorization be able to encrypt with nip04?
    pub nip04encrypt: bool,
    /// Should the authorization be able to decrypt with nip04?
    pub nip04decrypt: bool,
    /// Should the authorization be able to encrypt with nip44?
    pub nip44encrypt: bool,
    /// Should the authorization be able to decrypt with nip44?
    pub nip44decrypt: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            max_uses: 1,
            expires_at: None,
            get_pubkey: true,
            sign_kinds: None,
            nip04encrypt: true,
            nip04decrypt: true,
            nip44encrypt: true,
            nip44decrypt: true,
        }
    }
}
