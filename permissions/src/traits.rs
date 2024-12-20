use async_trait::async_trait;
use nostr_sdk::{Event, PublicKey};
use serde_json;

#[async_trait]
pub trait CustomPermission: Send + Sync {
    /// Snake case (lower_case_with_underscores) identifier is used to identify the permission.
    fn identifier(&self) -> &'static str;

    /// The config is a JSON object that contains the configuration for the permission.
    fn config(&self) -> serde_json::Value;

    /// A function that returns true if allowed to sign the event.
    async fn can_sign(&self, event: &Event) -> bool;

    /// A function that returns true if allowed to encrypt the event for the recipient.
    async fn can_encrypt(&self, event: &Event, recipient_pubkey: &PublicKey) -> bool;

    /// A function that returns true if allowed to decrypt the event for the sender.
    async fn can_decrypt(&self, event: &Event, sender_pubkey: &PublicKey) -> bool;
}

pub static AVAILABLE_PERMISSIONS: [&str; 3] =
    ["allowed_kinds", "content_filter", "encrypt_to_self"];
