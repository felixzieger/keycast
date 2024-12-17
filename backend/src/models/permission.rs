use chrono::DateTime;
use nostr_sdk::{Event, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Permission {
    pub id: u32,
    pub identifier: String,
    pub config: serde_json::Value,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

pub trait PolicyPermission {
    fn identifier(&self) -> &'static str;
    fn can_sign(&self, event: &Event) -> bool;
    fn can_encrypt(&self, recipient_pubkey: &PublicKey) -> bool;
    fn can_decrypt(&self, sender_pubkey: &PublicKey) -> bool;
}
