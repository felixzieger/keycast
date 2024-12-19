use crate::models::authorization::Authorization;
use std::collections::HashMap;
use std::process::{Child, Command};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProcessManagerError {
    #[error("Failed to spawn signing daemon")]
    Spawn,
    #[error("Failed to shutdown signing daemon")]
    Shutdown,
    #[error("Failed to get process")]
    GetProcess(#[from] std::io::Error),
    #[error("Failed to get environment variable")]
    EnvVar(#[from] std::env::VarError),
}

pub struct ProcessManager {
    processes: HashMap<u32, Child>, // auth_id -> process
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    pub async fn spawn_daemon(&mut self, auth: Authorization) -> Result<(), ProcessManagerError> {
        let child = Command::new(std::env::current_exe()?)
            .arg("signing-daemon")
            .env("AUTH_ID", auth.id.to_string())
            .spawn()
            .map_err(|_| ProcessManagerError::Spawn)?;

        self.processes.insert(auth.id, child);
        Ok(())
    }

    pub fn shutdown_daemon(&mut self, auth_id: u32) -> Result<(), ProcessManagerError> {
        if let Some(mut child) = self.processes.remove(&auth_id) {
            child.kill().map_err(|_| ProcessManagerError::Shutdown)?;
            child.wait().map_err(|_| ProcessManagerError::Shutdown)?;
        }
        Ok(())
    }
}
