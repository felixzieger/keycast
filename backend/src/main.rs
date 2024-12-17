mod api;
mod cli;
mod database;
mod encryption;
mod models;

use clap::Parser;
use cli::Cli;
use database::{Database, DatabaseError};
use dotenv::dotenv;
use encryption::{file_key_manager::FileKeyManager, KeyManager, KeyManagerError};
use once_cell::sync::OnceCell;
use sqlx::SqlitePool;
use std::env;
use std::path::PathBuf;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static DB: OnceCell<Database> = OnceCell::new();
static KEY_MANAGER: OnceCell<Box<dyn KeyManager>> = OnceCell::new();

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env file
    match dotenv() {
        Ok(_) => println!("Successfully loaded .env file"),
        Err(e) => println!("Error loading .env file: {}", e),
    };

    // Initialize tracing with debug level
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_path = PathBuf::from(env::var("DATABASE_URL").map_err(|_| "DATABASE_URL not set")?);
    initialize_db(db_path).await?;

    // Setup basic file based key manager for encryption
    let key_manager = FileKeyManager::new()?;
    set_key_manager(Box::new(key_manager))?;

    // Setup shutdown signal handler
    tokio::spawn(async {
        match signal::ctrl_c().await {
            Ok(()) => {
                println!("\nShutdown signal received, cleaning up...");
                tracing::info!("Shutdown signal received, cleaning up...");
                if let Some(db) = DB.get() {
                    db.pool.close().await;
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

pub async fn initialize_db(db_path: PathBuf) -> Result<(), DatabaseError> {
    let database = Database::new(db_path).await?;
    DB.set(database)
        .map_err(|_| DatabaseError::AlreadyInitialized)
}

pub fn get_db() -> Result<&'static Database, DatabaseError> {
    DB.get().ok_or(DatabaseError::NotInitialized)
}

pub fn get_db_pool() -> Result<&'static SqlitePool, DatabaseError> {
    DB.get()
        .ok_or(DatabaseError::NotInitialized)
        .map(|db| &db.pool)
}

pub fn set_key_manager(key_manager: Box<dyn KeyManager>) -> Result<(), KeyManagerError> {
    KEY_MANAGER
        .set(key_manager)
        .map_err(|_| KeyManagerError::AlreadyInitialized)
}

pub fn get_key_manager() -> Result<&'static dyn KeyManager, KeyManagerError> {
    KEY_MANAGER
        .get()
        .map(|b| b.as_ref())
        .ok_or(KeyManagerError::NotInitialized)
}
