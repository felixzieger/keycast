use dotenv::dotenv;
use keycast_api::models::authorization::Authorization;
use nostr_sdk::{Client, Keys};
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

    // TODO: Initialize nostr client and start processing events

    Ok(())
}
