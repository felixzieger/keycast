mod api;
mod authorization;
mod cli;
mod database;
mod models;

use clap::Parser;
use cli::Cli;
use database::{Database, DatabaseError};
use once_cell::sync::OnceCell;
use sqlx::SqlitePool;
use std::path::PathBuf;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static DB: OnceCell<Database> = OnceCell::new();

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing with debug level
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let db_path = project_root.join("keycast.db");
    initialize_db(db_path).await?;

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
