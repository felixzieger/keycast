use crate::types::authorization::AuthorizationError;
use crate::types::permission::{Permission, PermissionError};
use async_trait::async_trait;
use nostr::nips::nip46::Request;
use nostr_sdk::{Event, PublicKey};
use sqlx::SqlitePool;

/// Provides methods for validating an authorization against it's permissions and other properties in the context of a request
pub trait AuthorizationValidations {
    /// Check if the authorization is expired
    fn expired(&self) -> Result<bool, AuthorizationError>;
    /// Check if the authorization has no redeemable uses left
    fn fully_redeemed(&self, pool: &SqlitePool) -> Result<bool, AuthorizationError>;
    /// Check the authorizations permissions
    fn validate_permissions(
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
    fn can_sign(&self, event: &Event) -> bool;

    /// A function that returns true if allowed to encrypt the event for the recipient.
    fn can_encrypt(&self, event: &Event, recipient_pubkey: &PublicKey) -> bool;

    /// A function that returns true if allowed to decrypt the event for the sender.
    fn can_decrypt(&self, event: &Event, sender_pubkey: &PublicKey) -> bool;
}
