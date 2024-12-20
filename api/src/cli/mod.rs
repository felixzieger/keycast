use crate::api;
use crate::signer::signer_manager::{SignerManager, SignerManagerError};
use crate::state::{get_db_pool, get_key_manager};
use axum::http::HeaderValue;
use axum::Router;
use clap::{Parser, Subcommand};
use common::database::DatabaseError;
use common::encryption::KeyManagerError;
use thiserror::Error;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("Database: {0}")]
    Database(#[from] DatabaseError),

    #[error("Key: {0}")]
    Key(#[from] KeyManagerError),

    #[error("SignerManager: {0}")]
    SignerManager(#[from] SignerManagerError),
}

#[derive(Parser, Debug)]
#[clap(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start the API server (default)
    Server {
        #[command(subcommand)]
        command: ServerCommands,
    },
    /// Generate a master key in the workspace root
    GenerateMasterKey,
    /// Manage nostr remote signer processes
    Signer {
        #[command(subcommand)]
        command: SignerCommands,
    },
}

#[derive(Debug, Subcommand)]
enum ServerCommands {
    Start,
}

#[derive(Debug, Subcommand)]
enum SignerCommands {
    Start { auth_id: Option<String> },
    Stop { auth_id: Option<String> },
    List { auth_id: Option<String> },
}

impl Cli {
    pub async fn execute(self) -> Result<(), CliError> {
        match self.command {
            Commands::Server { command } => match command {
                ServerCommands::Start => {
                    let cors = CorsLayer::new()
                        .allow_origin("http://localhost:5173".parse::<HeaderValue>().unwrap())
                        .allow_methods(Any)
                        .allow_headers(Any);

                    let app = Router::new()
                        .nest("/api", api::http::routes(get_db_pool().unwrap().clone()))
                        .layer(TraceLayer::new_for_http())
                        .layer(cors);

                    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
                    println!("Listening on {}", listener.local_addr().unwrap());
                    tracing::info!("listening on {}", listener.local_addr().unwrap());

                    axum::serve(listener, app).await.unwrap();
                    Ok(())
                }
            },
            Commands::Signer { command } => match command {
                SignerCommands::Start { auth_id } => match auth_id {
                    Some(auth_id) => {
                        todo!()
                    }
                    None => {
                        let mut signer_manager = SignerManager::instance().write().await;
                        signer_manager
                            .run()
                            .await
                            .map_err(|e| CliError::SignerManager(e))
                    }
                },
                SignerCommands::Stop { auth_id } => match auth_id {
                    Some(auth_id) => {
                        todo!()
                    }
                    None => {
                        let mut signer_manager = SignerManager::instance().write().await;
                        signer_manager
                            .shutdown()
                            .map_err(|e| CliError::SignerManager(e))
                    }
                },
                SignerCommands::List { auth_id } => match auth_id {
                    Some(auth_id) => {
                        todo!()
                    }
                    None => {
                        let signer_manager = SignerManager::instance().read().await;
                        signer_manager
                            .list()
                            .map_err(|e| CliError::SignerManager(e))
                    }
                },
            },
            Commands::GenerateMasterKey => {
                let key_manager = get_key_manager().unwrap();
                key_manager
                    .generate_master_key()
                    .await
                    .map_err(|e| CliError::Key(e))
            }
        }
    }
}
