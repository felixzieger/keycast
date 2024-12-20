use dotenv::dotenv;
use keycast_api::encryption::file_key_manager::FileKeyManager;
use keycast_api::encryption::KeyManager;
use keycast_api::models::authorization::Authorization;
use nostr_connect::prelude::*;
use nostr_sdk::prelude::*;
use sqlx::SqlitePool;
use std::env;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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

    // Configure SQLite for concurrent access
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA busy_timeout=5000")
        .execute(&pool)
        .await?;

    tracing::info!("Starting signing daemon for authorization {}", auth_id);

    let authorization = Authorization::find(&pool, auth_id).await?;

    // Decrypt the bunker secret
    let key_manager = FileKeyManager::new()?;
    let decrypted_secret_bytes = key_manager.decrypt(&authorization.bunker_secret).await?;
    let signer_secret_key = SecretKey::from_slice(&decrypted_secret_bytes)?;

    // Stored key for this authentication
    let stored_key = authorization.stored_key().await?;
    let decrypted_stored_key_bytes = key_manager.decrypt(&stored_key.secret_key).await?;
    let user_secret_key = SecretKey::from_slice(&decrypted_stored_key_bytes)?;

    let keys = NostrConnectKeys {
        signer: Keys::new(signer_secret_key),
        user: Keys::new(user_secret_key),
    };

    let signer =
        NostrConnectRemoteSigner::new(keys, authorization.relays, Some(authorization.secret), None);

    Ok(())
}

struct SignerActions;

impl NostrConnectSignerActions for SignerActions {
    fn approve(&self, _request: NostrConnectRequest) -> Result<(), NostrConnectError> {
        // Check to see if we have any redeemable uses left
        // Loop through all permissions
        Ok(())
    }
}
