mod api;
mod cli;
mod models;
mod permissions;
mod signer;
mod state;

use crate::state::{get_db_pool, KeycastState, KEYCAST_STATE};
use clap::Parser;
use cli::Cli;
use common::database::Database;
use common::encryption::file_key_manager::FileKeyManager;
use dotenv::dotenv;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env file
    match dotenv() {
        Ok(_) => tracing::debug!("Successfully loaded .env file"),
        Err(e) => tracing::error!("Error loading .env file: {}", e),
    };

    // Initialize tracing with debug level
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Set up database
    let db_path = PathBuf::from(env::var("DATABASE_URL").map_err(|_| "DATABASE_URL not set")?);
    let database = Database::new(db_path).await?;

    // Setup basic file based key manager for encryption
    let key_manager = FileKeyManager::new()?;

    // Create a shared state with the database and key manager
    let state = Arc::new(KeycastState {
        db: database.pool,
        key_manager: Box::new(key_manager),
    });

    // Set the shared state in the once cell
    KEYCAST_STATE
        .set(state)
        .map_err(|_| "Failed to set KeycastState")?;

    // Setup shutdown signal handler
    tokio::spawn(async {
        match signal::ctrl_c().await {
            Ok(()) => {
                println!("\nShutdown signal received, cleaning up...");
                tracing::info!("Shutdown signal received, cleaning up...");
                if let Ok(db) = get_db_pool() {
                    db.close().await;
                }
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!("Error: {}", err);
                std::process::exit(1);
            }
        }
    });

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(_) => {
            // If parsing fails (no args or invalid args), use the serve command
            Cli::try_parse_from(["keycast", "serve"]).expect("Failed to parse default command")
        }
    };

    cli.execute().await?;

    Ok(())
}
