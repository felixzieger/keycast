use nostr_sdk::{Event, PublicKey};

#[allow(dead_code)]
pub trait CustomPermission {
    /// Snake case (lower_case_with_underscores) identifier is used to identify the permission.
    fn identifier(&self) -> &'static str;

    /// The config is a JSON object that contains the configuration for the permission.
    fn config(&self) -> serde_json::Value;

    /// A function that returns true if allowed to sign the event.
    fn can_sign(&self, event: &Event) -> bool;

    /// A function that returns true if allowed to encrypt the event for the recipient.
    fn can_encrypt(&self, event: &Event, recipient_pubkey: &PublicKey) -> bool;

    /// A function that returns true if allowed to decrypt the event for the sender.
    fn can_decrypt(&self, event: &Event, sender_pubkey: &PublicKey) -> bool;
}

pub static AVAILABLE_PERMISSIONS: [&str; 3] =
    ["allowed_kinds", "content_filter", "encrypt_to_self"];
