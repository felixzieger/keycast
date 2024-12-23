use crate::encryption::KeyManagerError;
use crate::traits::AuthorizationValidations;
use crate::types::permission::Permission;
use crate::types::policy::Policy;
use crate::types::stored_key::StoredKey;
use chrono::DateTime;
use nostr::nips::nip46::Request;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Encryption error: {0}")]
    Encryption(#[from] KeyManagerError),
    #[error("Invalid bunker secret key")]
    InvalidBunkerSecretKey,
}

/// A list of relays, this is used to store the relays that signers will listen on for an authorization
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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

/// An authorization is a set of permissions that belong to a team and can be used to control access to a team's stored keys
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct Authorization {
    /// The id of the authorization
    pub id: u32,
    /// The id of the stored key the authorization belongs to
    pub stored_key_id: u32,
    /// The generated secret connection uuid
    pub secret: String,
    /// The public key of the bunker nostr secret key
    pub bunker_public_key: String,
    /// The encrypted bunker nostr secret key
    pub bunker_secret: Vec<u8>,
    #[sqlx(try_from = "String")]
    /// The list of relays the authorization will listen on
    pub relays: Relays,
    /// The id of the policy the authorization belongs to
    pub policy_id: u32,
    /// The maximum number of uses for this authorization, None means unlimited
    pub max_uses: Option<u16>,
    /// The date and time at which this authorization expires, None means it never expires
    pub expires_at: Option<DateTime<chrono::Utc>>,
    /// The date and time the authorization was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the authorization was last updated
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
    pub bunker_connection_string: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct UserAuthorization {
    pub user_public_key: String,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

impl Authorization {
    /// Get the number of redemptions used for this authorization
    /// This method is synchronous/blocking so that we can use it in the signing daemon
    pub fn redemptions_sync(&self, pool: &SqlitePool) -> Result<u16, AuthorizationError> {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let count = rt.block_on(async {
            sqlx::query_scalar::<_, i64>(
                r#"
                SELECT COUNT(*) FROM user_authorizations WHERE authorization_id = ?
                "#,
            )
            .bind(self.id)
            .fetch_one(pool)
            .await
        })?;
        Ok(count as u16)
    }

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

    /// Get the stored key for this authorization
    pub async fn stored_key(&self, pool: &SqlitePool) -> Result<StoredKey, AuthorizationError> {
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

    /// Get the permissions for this authorization
    /// This method is synchronous/blocking so that we can use it in the signing daemon
    pub fn permissions_sync(
        &self,
        pool: &SqlitePool,
    ) -> Result<Vec<Permission>, AuthorizationError> {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let permissions = rt.block_on(async {
            sqlx::query_as::<_, Permission>(
                r#"
                SELECT p.* 
                FROM permissions p
                JOIN policy_permissions pp ON pp.permission_id = p.id
                JOIN policies pol ON pol.id = pp.policy_id
                WHERE pol.id = ?
                "#,
            )
            .bind(self.policy_id)
            .fetch_all(pool)
            .await
        })?;
        Ok(permissions)
    }

    /// Generate a connection string for the authorization
    /// bunker://<remote-signer-pubkey>?relay=<wss://relay-to-connect-on>&relay=<wss://another-relay-to-connect-on>&secret=<optional-secret-value>
    pub async fn bunker_connection_string(&self) -> Result<String, AuthorizationError> {
        let relays_arr = self
            .relays
            .0
            .iter()
            .map(|r| format!("relay={}", r))
            .collect::<Vec<String>>();

        Ok(format!(
            "bunker://{}?{}&secret={}",
            self.bunker_public_key,
            relays_arr.join("&"),
            self.secret,
        ))
    }
}

impl AuthorizationValidations for Authorization {
    fn expired(&self) -> Result<bool, AuthorizationError> {
        match self.expires_at {
            Some(expires_at) => Ok(expires_at < chrono::Utc::now()),
            None => Ok(false),
        }
    }

    fn fully_redeemed(&self, pool: &SqlitePool) -> Result<bool, AuthorizationError> {
        match self.max_uses {
            Some(max_uses) => {
                let redemptions = match self.redemptions_sync(pool) {
                    Ok(redemptions) => redemptions,
                    Err(e) => {
                        return Err(e);
                    }
                };
                Ok(redemptions >= max_uses)
            }
            None => Ok(false),
        }
    }

    fn validate_permissions(
        &self,
        pool: &SqlitePool,
        _request: &Request,
    ) -> Result<bool, AuthorizationError> {
        let permissions = self.permissions_sync(pool)?;

        for _permission in permissions {
            // TODO: Implement permission validation
        }
        Ok(true)
    }
}
