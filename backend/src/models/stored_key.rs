use crate::models::user::{User, UserError};
use chrono::DateTime;
use nostr_sdk::{Keys, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::SqlitePool;
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

    #[error("User is not authorized to perform this action")]
    NotAuthorized,

    #[error("User is not an admin of the team")]
    NotAdmin(#[from] UserError),
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct StoredKey {
    pub id: u32,
    pub team_id: u32,
    pub name: String,
    pub public_key: String, // hex pubkey
    pub secret_key: String, // hex secret key
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

impl StoredKey {
    pub async fn for_user(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
    ) -> Result<Vec<Self>, KeyError> {
        let query = "SELECT * FROM stored_keys WHERE team_id IN (SELECT team_id FROM team_users WHERE user_public_key = $1)";
        sqlx::query_as::<_, StoredKey>(query)
            .bind(user_pubkey.to_hex())
            .fetch_all(pool)
            .await
            .map_err(KeyError::from)
    }

    pub async fn create(
        team_id: u32,
        name: String,
        secret_key_string: String,
        pool: &SqlitePool,
    ) -> Result<Self, KeyError> {
        let secret_key = SecretKey::parse(&secret_key_string)?.to_secret_hex();
        let public_key = Keys::parse(&secret_key_string)?.public_key().to_hex();

        let stored_key = Self {
            id: 0, // Will be auto-incremented by the database
            team_id,
            name,
            public_key,
            secret_key,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let query = "INSERT INTO stored_keys (team_id, name, public_key, secret_key, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *";
        let persisted = sqlx::query_as::<_, StoredKey>(query)
            .bind(stored_key.team_id)
            .bind(&stored_key.name)
            .bind(&stored_key.public_key)
            .bind(&stored_key.secret_key)
            .bind(stored_key.created_at)
            .bind(stored_key.updated_at)
            .fetch_one(pool)
            .await?;

        Ok(persisted)
    }

    pub async fn update(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        team_id: u32,
        name: &str,
    ) -> Result<StoredKey, KeyError> {
        let mut tx = pool.begin().await?;

        if !User::is_team_admin(pool, user_pubkey, team_id).await? {
            return Err(KeyError::NotAuthorized);
        }

        let query = "UPDATE stored_keys SET name = $1 WHERE id = $2 RETURNING *";
        let persisted = sqlx::query_as::<_, StoredKey>(query)
            .bind(name)
            .bind(team_id)
            .fetch_one(&mut *tx)
            .await?;
        Ok(persisted)
    }
}
