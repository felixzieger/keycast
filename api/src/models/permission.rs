use crate::models::authorization::AuthorizationError;
use chrono::DateTime;
use nostr::nips::nip46::Request;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PermissionError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Permission {
    pub id: u32,
    pub identifier: String,
    pub config: serde_json::Value,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct PolicyPermission {
    pub id: u32,
    pub policy_id: u32,
    pub permission_id: u32,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}
