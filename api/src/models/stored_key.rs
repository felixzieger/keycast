use crate::encryption::KeyManagerError;
use crate::models::user::UserError;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Nostr Key Error: {0}")]
    NostrKey(#[from] nostr_sdk::key::Error),

    #[error("NIP-49 Error: {0}")]
    Nip49(#[from] nostr_sdk::nips::nip49::Error),

    #[error("NIP-19 Error: {0}")]
    Nip19(#[from] nostr_sdk::nips::nip19::Error),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("User is not an admin of the team")]
    NotAdmin(#[from] UserError),

    #[error("Key manager error: {0}")]
    KeyManager(#[from] KeyManagerError),
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct StoredKey {
    pub id: u32,
    pub team_id: u32,
    pub name: String,
    pub public_key: String, // hex pubkey
    #[sqlx(skip)]
    pub secret_key: Vec<u8>, // encrypted secret key in bytes
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicStoredKey {
    pub id: u32,
    pub team_id: u32,
    pub name: String,
    pub public_key: String,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

impl From<StoredKey> for PublicStoredKey {
    fn from(key: StoredKey) -> Self {
        Self {
            id: key.id,
            team_id: key.team_id,
            name: key.name,
            public_key: key.public_key,
            created_at: key.created_at,
            updated_at: key.updated_at,
        }
    }
}
