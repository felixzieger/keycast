use crate::types::authorization::AuthorizationError;
use crate::types::permission::{Permission, PermissionError};
use async_trait::async_trait;
use nostr::nips::nip46::Request;
use nostr_sdk::{PublicKey, UnsignedEvent};
use sqlx::SqlitePool;

/// Provides methods for validating an authorization against it's permissions and other properties in the context of a request
pub trait AuthorizationValidations {
    /// Check the authorization's policy & permissions
    fn validate_policy(
        &self,
        pool: &SqlitePool,
        request: &Request,
    ) -> Result<bool, AuthorizationError>;
}

/// A trait that represents a custom permission
#[async_trait]
pub trait CustomPermission: Send + Sync {
    /// Create a new instance of the permission from a database Permission
    fn from_permission(
        permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError>
    where
        Self: Sized;

    fn identifier(&self) -> &'static str;

    /// A function that returns true if allowed to sign the event.
    fn can_sign(&self, event: &UnsignedEvent) -> bool;

    /// A function that returns true if allowed to encrypt the content for the recipient.
    fn can_encrypt(&self, plaintext: &str, recipient_pubkey: &PublicKey) -> bool;

    /// A function that returns true if allowed to decrypt the content from the sender.
    fn can_decrypt(&self, ciphertext: &str, sender_pubkey: &PublicKey) -> bool;
}
