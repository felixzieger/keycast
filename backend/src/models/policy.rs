use chrono::DateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    pub id: u32,
    pub name: String,
    pub team_id: u32,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}
