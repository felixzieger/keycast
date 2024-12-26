use crate::{
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use nostr_sdk::{Event, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AllowedKindsConfig {
    pub sign: Option<Vec<u16>>,
    pub encrypt: Option<Vec<u16>>,
    pub decrypt: Option<Vec<u16>>,
}

pub struct AllowedKinds {
    config: AllowedKindsConfig,
}

#[async_trait]
impl CustomPermission for AllowedKinds {
    fn from_permission(
        permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError> {
        let parsed_config: AllowedKindsConfig =
            serde_json::from_value(permission.config.clone())
                .map_err(|e| PermissionError::InvalidConfig(e.to_string()))?;

        Ok(Box::new(Self {
            config: parsed_config,
        }))
    }

    fn identifier(&self) -> &'static str {
        "allowed_kinds"
    }

    fn can_sign(&self, event: &Event) -> bool {
        match &self.config.sign {
            None => true,
            Some(kinds) => kinds.contains(&event.kind.into()),
        }
    }

    fn can_encrypt(&self, event: &Event, _recipient_pubkey: &PublicKey) -> bool {
        match &self.config.encrypt {
            None => true,
            Some(kinds) => kinds.contains(&event.kind.into()),
        }
    }

    fn can_decrypt(&self, event: &Event, _sender_pubkey: &PublicKey) -> bool {
        match &self.config.decrypt {
            None => true,
            Some(kinds) => kinds.contains(&event.kind.into()),
        }
    }
}

#[test]
fn test_default() {
    let config = AllowedKindsConfig::default();
    assert!(config.sign.is_none());
    assert!(config.encrypt.is_none());
    assert!(config.decrypt.is_none());
}
