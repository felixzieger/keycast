use dotenv::dotenv;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_core::traits::AuthorizationValidations;
use keycast_core::types::authorization::Authorization;
use nostr::nips::nip46::Request;
use nostr_connect::prelude::*;
use sqlx::SqlitePool;
use std::env;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

struct SignerDaemon<T: AuthorizationValidations> {
    authorization: T,
    pool: SqlitePool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenv().ok();

    // Get configuration from environment
    let auth_id: u32 = env::var("AUTH_ID")?.parse()?;

    // Connect to the main application database
    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL not set")?;
    let pool = SqlitePool::connect(&database_url).await?;

    tracing::info!(target: "signing_daemon", "Starting signing daemon for authorization {:?}", auth_id);

    let authorization = Authorization::find(&pool, auth_id).await?;

    let signer_daemon = SignerDaemon {
        authorization,
        pool,
    };

    // Decrypt the bunker secret
    let key_manager = FileKeyManager::new()?;
    let decrypted_secret_bytes = key_manager
        .decrypt(&signer_daemon.authorization.bunker_secret)
        .await?;
    let signer_secret_key = SecretKey::from_slice(&decrypted_secret_bytes)?;

    // Decrypt the stored key for this authentication
    let stored_key = signer_daemon
        .authorization
        .stored_key(&signer_daemon.pool)
        .await?;
    let decrypted_stored_key_bytes = key_manager.decrypt(&stored_key.secret_key).await?;
    let user_secret_key = SecretKey::from_slice(&decrypted_stored_key_bytes)?;

    let keys = NostrConnectKeys {
        signer: Keys::new(signer_secret_key),
        user: Keys::new(user_secret_key),
    };

    let signer = NostrConnectRemoteSigner::new(
        keys,
        signer_daemon.authorization.relays.clone(),
        Some(signer_daemon.authorization.secret.clone()),
        None,
    )?;

    tracing::info!(target: "keycast_signer::signing_daemon", "Signing daemon for authorization {:?} started", auth_id);
    tracing::info!(target: "keycast_signer::signing_daemon", "Bunker signing URI: {:?}", signer.bunker_uri());

    // Start the signer with custom actions
    signer.serve(SignerActions::new(signer_daemon)).await?;

    Ok(())
}

struct SignerActions<T: AuthorizationValidations> {
    signer_daemon: SignerDaemon<T>,
}

impl<T: AuthorizationValidations> SignerActions<T> {
    fn new(signer_daemon: SignerDaemon<T>) -> Self {
        Self { signer_daemon }
    }
}

impl<T: AuthorizationValidations> NostrConnectSignerActions for SignerActions<T> {
    fn approve(&self, request: &Request) -> bool {
        tracing::debug!(target: "keycast_signer::signing_daemon", "Evaluating request: {:?}", request);

        // Check to see if the authorization is expired
        match self.signer_daemon.authorization.expired() {
            Ok(true) => {
                tracing::error!(target: "keycast_signer::signing_daemon", "Authorization expired");
                return false;
            }
            Ok(false) => (),
            Err(e) => {
                tracing::error!(target: "keycast_signer::signing_daemon", "Error checking if authorization is expired: {:?}", e);
                return false;
            }
        }

        // Check to see if we have any redemptions left to use
        match self
            .signer_daemon
            .authorization
            .fully_redeemed(&self.signer_daemon.pool)
        {
            Ok(true) => {
                tracing::error!(target: "keycast_signer::signing_daemon", "Authorization fully redeemed");
                return false;
            }
            Ok(false) => (),
            Err(e) => {
                tracing::error!(target: "keycast_signer::signing_daemon", "Error checking if authorization is fully redeemed: {:?}", e);
                return false;
            }
        }

        true

        // Loop through each permission attached to the authentication

        // match request {
        //     Request::Connect { public_key, secret } => {
        //         tracing::info!(target: "keycast_signer::signing_daemon", "Connect request received");
        //         return true;
        //     }
        //     Request::GetPublicKey => {
        //         tracing::info!(target: "keycast_signer::signing_daemon", "Get public key request received");
        //         return true;
        //     }
        //     Request::SignEvent(event) => {
        //         tracing::info!(target: "keycast_signer::signing_daemon", "Sign event request received");
        //         return true;
        //     }
        //     Request::GetRelays => {
        //         tracing::info!(target: "keycast_signer::signing_daemon", "Get relays request received");
        //         return true;
        //     }
        //     Request::Nip04Encrypt { public_key, text } => {
        //         tracing::info!(target: "keycast_signer::signing_daemon", "NIP04 encrypt request received");
        //         return true;
        //     }
        //     Request::Nip04Decrypt {
        //         public_key,
        //         ciphertext,
        //     } => {
        //         tracing::info!(target: "keycast_signer::signing_daemon", "NIP04 decrypt request received");
        //         return true;
        //     }
        //     Request::Nip44Encrypt { public_key, text } => {
        //         tracing::info!(target: "keycast_signer::signing_daemon", "NIP44 encrypt request received");
        //         return true;
        //     }
        //     Request::Nip44Decrypt {
        //         public_key,
        //         ciphertext,
        //     } => {
        //         tracing::info!(target: "keycast_signer::signing_daemon", "NIP44 decrypt request received");
        //         return true;
        //     }
        //     Request::Ping => {
        //         tracing::info!(target: "keycast_signer::signing_daemon", "Ping request received");
        //         return true;
        //     }
        //     _ => {
        //         tracing::error!(target: "keycast_signer::signing_daemon", "Unsupported request: {:?}", request);
        //         return false;
        //     }
        // }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keycast_core::types::authorization::AuthorizationError;

    // Mock Authorization for testing
    struct MockAuthorization {
        expired: bool,
        max_uses: Option<i64>,
        current_redemptions: i64,
    }

    impl AuthorizationValidations for MockAuthorization {
        fn expired(&self) -> Result<bool, AuthorizationError> {
            Ok(self.expired)
        }

        fn fully_redeemed(&self, _pool: &SqlitePool) -> Result<bool, AuthorizationError> {
            Ok(match self.max_uses {
                Some(max) => self.current_redemptions >= max,
                None => false, // No maximum uses means it can never be fully redeemed
            })
        }
        fn validate_permissions(
            &self,
            _pool: &SqlitePool,
            _request: &Request,
        ) -> Result<bool, AuthorizationError> {
            Ok(true)
        }
    }

    // Helper to create SignerDaemon with mock authorization
    async fn create_test_signer(mock_auth: MockAuthorization) -> SignerDaemon<MockAuthorization> {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        SignerDaemon {
            authorization: mock_auth,
            pool,
        }
    }

    #[tokio::test]
    async fn test_approve_expired_authorization() {
        let mock_auth = MockAuthorization {
            expired: true,
            max_uses: None,
            current_redemptions: 0,
        };
        let signer_daemon = create_test_signer(mock_auth).await;
        let signer_actions = SignerActions::new(signer_daemon);

        assert!(!signer_actions.approve(&Request::Ping));
    }

    #[tokio::test]
    async fn test_approve_max_uses_exceeded() {
        let mock_auth = MockAuthorization {
            expired: false,
            max_uses: Some(5),
            current_redemptions: 5,
        };
        let signer_daemon = create_test_signer(mock_auth).await;
        let signer_actions = SignerActions::new(signer_daemon);

        assert!(!signer_actions.approve(&Request::Ping));
    }

    #[tokio::test]
    async fn test_approve_valid_authorization() {
        let mock_auth = MockAuthorization {
            expired: false,
            max_uses: Some(5),
            current_redemptions: 4,
        };
        let signer_daemon = create_test_signer(mock_auth).await;
        let signer_actions = SignerActions::new(signer_daemon);

        assert!(signer_actions.approve(&Request::Ping));
    }

    #[tokio::test]
    async fn test_approve_no_max_uses() {
        let mock_auth = MockAuthorization {
            expired: false,
            max_uses: None,
            current_redemptions: 100,
        };
        let signer_daemon = create_test_signer(mock_auth).await;
        let signer_actions = SignerActions::new(signer_daemon);

        assert!(signer_actions.approve(&Request::Ping));
    }
}
