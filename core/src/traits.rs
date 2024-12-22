use crate::types::authorization::AuthorizationError;
use crate::types::permission::Permission;
use async_trait::async_trait;
use nostr::nips::nip46::Request;
use nostr_sdk::{Event, PublicKey};
use serde_json;
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
pub trait CustomPermission: Send + Sync
where
    Self: TryFrom<Permission> + From<Permission>,
{
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
