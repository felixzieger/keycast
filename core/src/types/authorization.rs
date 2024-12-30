use crate::encryption::KeyManagerError;
use crate::traits::AuthorizationValidations;
use crate::traits::CustomPermission;
use crate::types::permission::Permission;
use crate::types::policy::Policy;
use crate::types::stored_key::StoredKey;
use chrono::DateTime;
use nostr::nips::nip46::Request;
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use thiserror::Error;
use urlencoding;

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Encryption error: {0}")]
    Encryption(#[from] KeyManagerError),
    #[error("Invalid bunker secret key")]
    InvalidBunkerSecretKey,
    #[error("Authorization is expired")]
    Expired,
    #[error("Authorization is fully redeemed")]
    FullyRedeemed,
    #[error("Invalid secret")]
    InvalidSecret,
    #[error("Unauthorized by permission")]
    Unauthorized,
    #[error("Unsupported request")]
    UnsupportedRequest,
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
    pub fn redemptions_count_sync(&self, pool: &SqlitePool) -> Result<u16, AuthorizationError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let count = sqlx::query_scalar::<_, i64>(
                    r#"
                    SELECT COUNT(*) FROM user_authorizations WHERE authorization_id = ?
                    "#,
                )
                .bind(self.id)
                .fetch_one(pool)
                .await?;
                Ok(count as u16)
            })
        })
    }

    pub fn redemptions_pubkeys_sync(
        &self,
        pool: &SqlitePool,
    ) -> Result<Vec<PublicKey>, AuthorizationError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let pubkeys = sqlx::query_scalar::<_, String>(
                    r#"
                    SELECT user_public_key FROM user_authorizations WHERE authorization_id = ?
                    "#,
                )
                .bind(self.id)
                .fetch_all(pool)
                .await?;
                Ok(pubkeys
                    .iter()
                    .filter_map(|p| PublicKey::from_hex(p).ok())
                    .collect())
            })
        })
    }

    pub fn create_redemption_sync(
        &self,
        pool: &SqlitePool,
        pubkey: &PublicKey,
    ) -> Result<(), AuthorizationError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                // Check if the user exists
                let user = sqlx::query_scalar::<_, String>(
                    r#"
                    SELECT public_key FROM users WHERE public_key = ?
                    "#,
                )
                .bind(pubkey.to_hex())
                .fetch_optional(pool)
                .await?;

                // Create the user if needed
                if user.is_none() {
                    tracing::info!(target: "keycast_signer::signer_daemon", "Creating new user for pubkey: {:?}", pubkey);
                    sqlx::query(
                        r#"
                        INSERT INTO users (public_key, created_at, updated_at)
                        VALUES (?, ?, ?)
                        "#,
                    )
                    .bind(pubkey.to_hex())
                    .bind(chrono::Utc::now())
                    .bind(chrono::Utc::now())
                    .execute(pool)
                    .await?;
                }

                // Create the user authorization
                sqlx::query(
                    r#"
                    INSERT INTO user_authorizations (authorization_id, user_public_key, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                    "#,
                )
                .bind(self.id)
                .bind(pubkey.to_hex())
                .bind(chrono::Utc::now())
                .bind(chrono::Utc::now())
                .execute(pool)
                .await?;
                Ok(())
            })
        })
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
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let permissions = sqlx::query_as::<_, Permission>(
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
                .await?;
                Ok(permissions)
            })
        })
    }

    /// Generate a connection string for the authorization
    /// bunker://<remote-signer-pubkey>?relay=<encoded-relay-1,encoded-relay-2>&secret=<encoded-secret>
    pub async fn bunker_connection_string(&self) -> Result<String, AuthorizationError> {
        let relay_params = self
            .relays
            .0
            .iter()
            .map(|r| format!("relay={}", urlencoding::encode(r)))
            .collect::<Vec<_>>()
            .join("&");

        Ok(format!(
            "bunker://{}?{}&secret={}",
            self.bunker_public_key,
            relay_params,
            urlencoding::encode(&self.secret),
        ))
    }

    fn expired(&self) -> Result<bool, AuthorizationError> {
        match self.expires_at {
            Some(expires_at) => Ok(expires_at < chrono::Utc::now()),
            None => Ok(false),
        }
    }

    fn fully_redeemed(&self, pool: &SqlitePool) -> Result<bool, AuthorizationError> {
        match self.max_uses {
            Some(max_uses) => {
                let redemptions = match self.redemptions_count_sync(pool) {
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
}

impl AuthorizationValidations for Authorization {
    fn validate_policy(
        &self,
        pool: &SqlitePool,
        pubkey: &PublicKey,
        request: &Request,
    ) -> Result<bool, AuthorizationError> {
        // Before anything, check if the authorization is expired
        if self.expired()? {
            return Err(AuthorizationError::Expired);
        }

        // Approve straight away if it's just a ping request, for now?
        if *request == Request::Ping {
            return Ok(true);
        }

        // Convert database permissions to custom permissions
        let permissions = self.permissions_sync(pool)?;
        let custom_permissions: Result<Vec<Box<dyn CustomPermission>>, _> = permissions
            .iter()
            .map(|p| p.to_custom_permission())
            .collect();
        let custom_permissions =
            custom_permissions.expect("Failed to convert permissions to custom permissions");

        match request {
            Request::Connect { public_key, secret } => {
                tracing::info!(target: "keycast_signer::signer_daemon", "Connect request received");
                // Check the public key is the same as the bunker public key
                if public_key.to_hex() != self.bunker_public_key {
                    return Err(AuthorizationError::Unauthorized);
                }
                // Check if the authorization is fully redeemed
                if self.fully_redeemed(pool)? {
                    return Err(AuthorizationError::FullyRedeemed);
                }
                // Check that secret is correct
                match secret {
                    Some(ref s) if s != &self.secret => {
                        return Err(AuthorizationError::InvalidSecret)
                    }
                    _ => {}
                }
                // Create a new user authorization if we don't already have one for the requesting pubkey
                if !self.redemptions_pubkeys_sync(pool)?.contains(pubkey) {
                    tracing::info!(target: "keycast_signer::signer_daemon", "Creating new user authorization for pubkey: {:?}", pubkey);
                    self.create_redemption_sync(pool, pubkey)?;
                }
                Ok(true)
            }
            Request::GetPublicKey => {
                tracing::info!(target: "keycast_signer::signer_daemon", "Get public key request received");
                // Double check that the pubkey has connected to/redeemed this authorization
                Ok(self.redemptions_pubkeys_sync(pool)?.contains(pubkey))
            }
            Request::SignEvent(event) => {
                tracing::info!(target: "keycast_signer::signer_daemon", "Sign event request received");
                for permission in custom_permissions {
                    if !permission.can_sign(event) {
                        return Err(AuthorizationError::Unauthorized);
                    }
                }
                Ok(true)
            }
            Request::GetRelays => {
                tracing::info!(target: "keycast_signer::signer_daemon", "Get relays request received");
                Ok(true)
            }
            Request::Nip04Encrypt { public_key, text }
            | Request::Nip44Encrypt { public_key, text } => {
                tracing::info!(target: "keycast_signer::signer_daemon", "NIP04 encrypt request received");
                for permission in custom_permissions {
                    if !permission.can_encrypt(text, pubkey, public_key) {
                        return Err(AuthorizationError::Unauthorized);
                    }
                }
                Ok(true)
            }
            Request::Nip04Decrypt {
                public_key,
                ciphertext,
            }
            | Request::Nip44Decrypt {
                public_key,
                ciphertext,
            } => {
                tracing::info!(target: "keycast_signer::signer_daemon", "NIP04 decrypt request received");
                for permission in custom_permissions {
                    if !permission.can_decrypt(ciphertext, public_key, pubkey) {
                        return Err(AuthorizationError::Unauthorized);
                    }
                }
                Ok(true)
            }
            // We check this earlier but to complete the match statement, we need to return true here
            Request::Ping => {
                tracing::info!(target: "keycast_signer::signer_daemon", "Ping request received");
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use nostr::nips::nip46::Request;
    use nostr_sdk::{Keys, PublicKey};
    // Helper function to create a test database connection
    async fn setup_test_db() -> SqlitePool {
        SqlitePool::connect("sqlite::memory:").await.unwrap()
    }

    // Helper function to create a test authorization
    async fn create_test_authorization(
        pool: &SqlitePool,
        max_uses: Option<u16>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Authorization {
        // Create policies table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        // Insert test policy
        sqlx::query(
            r#"
            INSERT INTO policies (name, description, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind("test_policy")
        .bind("A test policy")
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(pool)
        .await
        .unwrap();

        // First create necessary tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS authorizations (
                id INTEGER PRIMARY KEY,
                stored_key_id INTEGER,
                secret TEXT,
                bunker_public_key TEXT,
                bunker_secret BLOB,
                relays TEXT,
                policy_id INTEGER,
                max_uses INTEGER,
                expires_at TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_authorizations (
                authorization_id INTEGER,
                user_public_key TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        // Insert test authorization
        let keys = Keys::generate();
        let auth = Authorization {
            id: 0,
            stored_key_id: 1,
            secret: "test_secret".to_string(),
            bunker_public_key: keys.public_key().to_hex(),
            bunker_secret: keys.secret_key().to_secret_bytes().to_vec(), // normally this would be encrypted
            relays: Relays(vec!["wss://test.relay".to_string()]),
            policy_id: 1,
            max_uses,
            expires_at,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        sqlx::query(
            r#"
            INSERT INTO authorizations 
            (stored_key_id, secret, bunker_public_key, bunker_secret, relays, policy_id, max_uses, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(auth.stored_key_id)
        .bind(&auth.secret)
        .bind(&auth.bunker_public_key)
        .bind(&auth.bunker_secret)
        .bind(serde_json::to_string(&auth.relays.0).unwrap())
        .bind(auth.policy_id)
        .bind(auth.max_uses)
        .bind(auth.expires_at)
        .bind(auth.created_at)
        .bind(auth.updated_at)
        .execute(pool)
        .await
        .unwrap();

        auth
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_expired() {
        let pool = setup_test_db().await;

        // Test non-expired authorization
        let future_date = Utc::now() + Duration::hours(24);
        let auth = create_test_authorization(&pool, None, Some(future_date)).await;
        assert!(!auth.expired().unwrap());

        // Test expired authorization
        let past_date = Utc::now() - Duration::hours(24);
        let auth = create_test_authorization(&pool, None, Some(past_date)).await;
        assert!(auth.expired().unwrap());

        // Test never-expiring authorization
        let auth = create_test_authorization(&pool, None, None).await;
        assert!(!auth.expired().unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_fully_redeemed() {
        let pool = setup_test_db().await;

        // Test authorization with no redemptions
        let auth = create_test_authorization(&pool, Some(2), None).await;
        assert!(!auth.fully_redeemed(&pool).unwrap());

        // Add some redemptions
        sqlx::query(
            "INSERT INTO user_authorizations (authorization_id, user_public_key, created_at, updated_at) 
             VALUES (?, ?, ?, ?)"
        )
        .bind(auth.id)
        .bind("test_user")
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();

        // Test partially redeemed
        assert!(!auth.fully_redeemed(&pool).unwrap());

        // Add another redemption to reach max
        sqlx::query(
            "INSERT INTO user_authorizations (authorization_id, user_public_key, created_at, updated_at) 
             VALUES (?, ?, ?, ?)"
        )
        .bind(auth.id)
        .bind("test_user2")
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();

        // Test fully redeemed
        assert!(auth.fully_redeemed(&pool).unwrap());

        // Test unlimited uses
        let auth = create_test_authorization(&pool, None, None).await;
        assert!(!auth.fully_redeemed(&pool).unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_validate_policy() {
        let pool = setup_test_db().await;

        // Create test tables for permissions
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY,
                identifier TEXT,
                name TEXT,
                description TEXT
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS policy_permissions (
                policy_id INTEGER,
                permission_id INTEGER
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let auth = create_test_authorization(&pool, None, None).await;
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        // Test with a simple request
        let request = Request::Connect {
            public_key: PublicKey::from_hex(&auth.bunker_public_key).unwrap(),
            secret: Some(auth.secret.clone()),
        };

        // This should return true as per current implementation
        assert!(auth.validate_policy(&pool, &pubkey, &request).unwrap());
    }
}
