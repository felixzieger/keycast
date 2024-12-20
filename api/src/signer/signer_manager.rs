use crate::models::authorization::{Authorization, AuthorizationError};
use crate::state::{get_db_pool, StateError};
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::process::{Child, Command};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum SignerManagerError {
    #[error("Failed to get database pool")]
    DatabasePool(#[from] StateError),
    #[error("Failed to get authorizations")]
    Authorizations(#[from] AuthorizationError),
    #[error("Failed to spawn signing daemon")]
    Spawn,
    #[error("Failed to shutdown signing daemon")]
    Shutdown,
    #[error("Failed to get process")]
    GetProcess(#[from] std::io::Error),
    #[error("Failed to get environment variable")]
    EnvVar(#[from] std::env::VarError),
    #[error("Failed to find signing_daemon binary")]
    SigningDaemonBinary,
}

#[derive(Default)]
pub struct SignerManager {
    signer_processes: HashMap<u32, Child>, // auth_id -> process
}

static INSTANCE: OnceCell<RwLock<SignerManager>> = OnceCell::new();

impl SignerManager {
    pub fn instance() -> &'static RwLock<SignerManager> {
        INSTANCE.get_or_init(|| RwLock::new(SignerManager::new()))
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run(&mut self) -> Result<(), SignerManagerError> {
        let pool = get_db_pool()?;

        // Get all authorizations, including expired ones so we can provide user feedback
        let authorization_ids = Authorization::all_ids(pool).await?;

        tracing::debug!(
            "Starting signer processes for {} authorizations",
            authorization_ids.len()
        );

        let mut failed = Vec::new();
        for auth_id in &authorization_ids {
            match self.spawn_signer_process(*auth_id) {
                Ok(_) => (),
                Err(e) => {
                    failed.push(*auth_id);
                    tracing::error!(
                        "Failed to start signer process for authorization {}: {}",
                        auth_id,
                        e
                    );
                }
            }
        }

        tracing::debug!(
            "Started signer processes for {} authorizations",
            authorization_ids.len()
        );
        if !failed.is_empty() {
            tracing::warn!(
                "Failed to start signer processes for {} authorizations",
                failed.len()
            );
        }

        // Start any monitoring processes we need - we need to monitor for processes that are exprired and stop them
        Ok(())
    }

    /// Shutdown all signer processes
    pub fn shutdown(&mut self) -> Result<(), SignerManagerError> {
        let auth_ids: Vec<u32> = self.signer_processes.keys().cloned().collect();
        for auth_id in auth_ids {
            self.shutdown_signer_process(&auth_id)?;
        }
        Ok(())
    }

    fn spawn_signer_process(&mut self, auth_id: u32) -> Result<(), SignerManagerError> {
        let binary_path = std::env::current_exe()?
            .parent()
            .ok_or(SignerManagerError::Spawn)?
            .join("signing_daemon");

        if !binary_path.exists() {
            return Err(SignerManagerError::SigningDaemonBinary);
        }

        tracing::info!("Starting signer process for authorization {}", auth_id);

        let child = Command::new(binary_path)
            .env("AUTH_ID", auth_id.to_string())
            .spawn()
            .map_err(|_| SignerManagerError::Spawn)?;

        self.signer_processes.insert(auth_id, child);
        Ok(())
    }

    fn shutdown_signer_process(&mut self, auth_id: &u32) -> Result<(), SignerManagerError> {
        if let Some(mut child) = self.signer_processes.remove(auth_id) {
            child.kill().map_err(|_| SignerManagerError::Shutdown)?;
            child.wait().map_err(|_| SignerManagerError::Shutdown)?;
        }
        Ok(())
    }
}
