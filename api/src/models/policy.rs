use crate::models::permission::Permission;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

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
