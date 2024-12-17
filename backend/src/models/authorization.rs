use crate::models::policy::Policy;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Relays(Vec<String>);

impl TryFrom<String> for Relays {
    type Error = serde_json::Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(Relays(serde_json::from_str(&s)?))
    }
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Authorization {
    pub id: u32,
    pub stored_key_id: u32,
    pub secret: String,
    pub bunker_nsec: String,
    #[sqlx(try_from = "String")]
    pub relays: Relays,
    pub policy_id: u32,
    pub max_uses: Option<u16>,
    pub expires_at: Option<DateTime<chrono::Utc>>,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct AuthorizationWithPolicy {
    #[sqlx(flatten)]
    pub authorization: Authorization,
    #[sqlx(flatten)]
    pub policy: Policy,
}
