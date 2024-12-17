pub mod keys;
use crate::api;
use crate::database::DatabaseError;
use crate::get_db_pool;
use crate::models::stored_key::KeyError;
use axum::http::HeaderValue;
use axum::Router;
use clap::{Parser, Subcommand};
use thiserror::Error;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("DatabaseError: {0}")]
    DatabaseError(#[from] DatabaseError),

    #[error("KeyError: {0}")]
    KeyError(#[from] KeyError),
}

#[derive(Parser, Debug)]
#[clap(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: EntityType,
}

#[derive(Debug, Subcommand)]
pub enum EntityType {
    Serve,
}

impl Cli {
    pub async fn execute(self) -> Result<(), CliError> {
        match self.command {
            EntityType::Serve => {
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
        }
    }
}
