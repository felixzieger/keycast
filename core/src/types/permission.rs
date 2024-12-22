use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PermissionError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// A permission is database representation of a CustomPermission trait
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Permission {
    /// The id of the permission
    pub id: u32,
    /// The identifier of the permission
    pub identifier: String,
    /// The configuration of the permission
    pub config: serde_json::Value,
    /// The date and time the permission was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the permission was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

/// A policy permission is a join table between a policy and a permission
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct PolicyPermission {
    /// The id of the policy permission
    pub id: u32,
    /// The id of the policy
    pub policy_id: u32,
    /// The id of the permission
    pub permission_id: u32,
    /// The date and time the policy permission was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the policy permission was last updated
    pub updated_at: DateTime<chrono::Utc>,
}
