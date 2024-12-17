use chrono::DateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Authorization {
    pub id: u32,
    pub stored_key_id: u32,
    pub secret: String,
    pub bunker_nsec: String,
    pub relays: Vec<String>,
    pub policy_id: u32,
    pub max_uses: Option<u16>,
    pub expires_at: Option<DateTime<chrono::Utc>>,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}
