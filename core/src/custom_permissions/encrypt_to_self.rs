use crate::{
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use nostr_sdk::{Event, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EncryptToSelfConfig {}

pub struct EncryptToSelf {}

#[async_trait]
impl CustomPermission for EncryptToSelf {
    fn from_permission(
        _permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError> {
        Ok(Box::new(Self {}))
    }

    fn identifier(&self) -> &'static str {
        "encrypt_to_self"
    }

    // This permission doesn't care about signing events
    fn can_sign(&self, _event: &Event) -> bool {
        true
    }

    fn can_encrypt(&self, event: &Event, recipient_pubkey: &PublicKey) -> bool {
        event.pubkey == *recipient_pubkey
    }

    fn can_decrypt(&self, event: &Event, sender_pubkey: &PublicKey) -> bool {
        event.pubkey == *sender_pubkey
    }
}
