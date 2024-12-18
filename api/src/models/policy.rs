use crate::models::permission::Permission;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Policy not found")]
    NotFound,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Policy {
    pub id: u32,
    pub name: String,
    pub team_id: u32,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct PolicyWithPermissions {
    #[sqlx(flatten)]
    pub policy: Policy,
    #[sqlx(default)]
    pub permissions: Vec<Permission>,
}
