use crate::models::policy::Policy;
use crate::models::stored_key::StoredKey;
use crate::state::{get_db_pool, get_key_manager, StateError};
use chrono::DateTime;
use common::encryption::KeyManagerError;
use nostr_sdk::{Keys, SecretKey};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::SqlitePool;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Encryption error: {0}")]
    Encryption(#[from] KeyManagerError),
    #[error("Invalid bunker secret key")]
    InvalidBunkerSecretKey,
    #[error("State error: {0}")]
    State(#[from] StateError),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Relays(Vec<String>);

impl IntoIterator for Relays {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Relays {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl TryFrom<String> for Relays {
    type Error = serde_json::Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(Relays(serde_json::from_str(&s)?))
    }
}

#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct Authorization {
    pub id: u32,
    pub stored_key_id: u32,
    /// The secret connection uuid
    pub secret: String,
    /// The encrypted bunker secret key
    pub bunker_secret: Vec<u8>,
    #[sqlx(try_from = "String")]
    pub relays: Relays,
    pub policy_id: u32,
    pub max_uses: Option<u16>,
    pub expires_at: Option<DateTime<chrono::Utc>>,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct AuthorizationWithPolicy {
    #[sqlx(flatten)]
    pub authorization: Authorization,
    #[sqlx(flatten)]
    pub policy: Policy,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct AuthorizationWithRelations {
    #[sqlx(flatten)]
    pub authorization: Authorization,
    #[sqlx(flatten)]
    pub policy: Policy,
    pub users: Vec<UserAuthorization>,
    pub connection_string: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct UserAuthorization {
    pub user_public_key: String,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

impl Authorization {
    pub async fn find(pool: &SqlitePool, id: u32) -> Result<Self, AuthorizationError> {
        let authorization = sqlx::query_as::<_, Authorization>(
            r#"
            SELECT * FROM authorizations WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_one(pool)
        .await?;
        Ok(authorization)
    }

    pub async fn all(pool: &SqlitePool) -> Result<Vec<Self>, AuthorizationError> {
        let authorizations = sqlx::query_as::<_, Authorization>(
            r#"
            SELECT * FROM authorizations
            "#,
        )
        .fetch_all(pool)
        .await?;
        Ok(authorizations)
    }

    pub async fn all_ids(pool: &SqlitePool) -> Result<Vec<u32>, AuthorizationError> {
        let authorizations = sqlx::query_scalar::<_, u32>(
            r#"
            SELECT id FROM authorizations
            "#,
        )
        .fetch_all(pool)
        .await?;
        Ok(authorizations)
    }

    pub async fn stored_key(&self) -> Result<StoredKey, AuthorizationError> {
        let pool = get_db_pool()?;

        let stored_key = sqlx::query_as::<_, StoredKey>(
            r#"
            SELECT * FROM stored_keys WHERE id = ?
            "#,
        )
        .bind(self.stored_key_id)
        .fetch_one(pool)
        .await?;
        Ok(stored_key)
    }

    /// Generate a connection string for the authorization
    /// bunker://<remote-signer-pubkey>?relay=<wss://relay-to-connect-on>&relay=<wss://another-relay-to-connect-on>&secret=<optional-secret-value>
    pub async fn connection_string(&self) -> Result<String, AuthorizationError> {
        let key_manager = get_key_manager().unwrap();

        tracing::debug!("Decrypting bunker secret {:?}", self.bunker_secret);
        let decryped_bunker_secret = key_manager.decrypt(&self.bunker_secret).await?;
        tracing::debug!(
            "Decrypted data (len={}): {:?}",
            decryped_bunker_secret.len(),
            decryped_bunker_secret
        );

        let bunker_secret = SecretKey::from_slice(&decryped_bunker_secret).map_err(|e| {
            tracing::error!("Failed to create SecretKey: {}", e);
            AuthorizationError::InvalidBunkerSecretKey
        })?;
        let keys = Keys::new(bunker_secret);

        let relays_arr = self
            .relays
            .0
            .iter()
            .map(|r| format!("relay={}", r))
            .collect::<Vec<String>>();

        Ok(format!(
            "bunker://{}?{}&secret={}",
            keys.public_key.to_hex(),
            relays_arr.join("&"),
            self.secret,
        ))
    }
}
