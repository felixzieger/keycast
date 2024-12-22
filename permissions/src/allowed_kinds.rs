use async_trait::async_trait;
use keycast_core::traits::CustomPermission;
use keycast_core::types::permission::Permission;
use nostr_sdk::{Event, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AllowedKindsConfig {
    pub sign: Option<Vec<u16>>,
    pub encrypt: Option<Vec<u16>>,
    pub decrypt: Option<Vec<u16>>,
}

impl From<AllowedKindsConfig> for serde_json::Value {
    fn from(config: AllowedKindsConfig) -> Self {
        serde_json::to_value(config).unwrap()
    }
}

impl From<serde_json::Value> for AllowedKindsConfig {
    fn from(value: serde_json::Value) -> Self {
        serde_json::from_value(value).unwrap()
    }
}

pub struct AllowedKinds {
    config: AllowedKindsConfig,
}

impl From<Permission> for AllowedKinds {
    fn from(permission: Permission) -> Self {
        Self {
            config: AllowedKindsConfig::from(permission.config),
        }
    }
}

#[async_trait]
impl CustomPermission for AllowedKinds {
    fn identifier(&self) -> &'static str {
        "allowed_kinds"
    }

    fn config(&self) -> serde_json::Value {
        self.config.clone().into()
    }

    async fn can_sign(&self, event: &Event) -> bool {
        match &self.config.sign {
            None => true,
            Some(kinds) => kinds.contains(&event.kind.into()),
        }
    }

    async fn can_encrypt(&self, event: &Event, _recipient_pubkey: &PublicKey) -> bool {
        match &self.config.encrypt {
            None => true,
            Some(kinds) => kinds.contains(&event.kind.into()),
        }
    }

    async fn can_decrypt(&self, event: &Event, _sender_pubkey: &PublicKey) -> bool {
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
