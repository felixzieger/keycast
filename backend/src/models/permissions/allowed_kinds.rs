use crate::models::permission::PolicyPermission;
use nostr_sdk::Event;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AllowedKindsConfig {
    pub sign: Option<Vec<u16>>,
    pub encrypt: Option<Vec<u16>>,
    pub decrypt: Option<Vec<u16>>,
}

/// Default to allow all kinds (NONE means allow all)
impl Default for AllowedKindsConfig {
    fn default() -> Self {
        Self {
            sign: None,
            encrypt: None,
            decrypt: None,
        }
    }
}

pub struct AllowedKinds {
    config: AllowedKindsConfig,
}

impl AllowedKinds {
    pub fn new(config: AllowedKindsConfig) -> Self {
        Self { config }
    }
}

impl PolicyPermission for AllowedKinds {
    fn identifier() -> &'static str {
        "allowed_kinds"
    }

    fn can_sign(&self, event: &Event) -> bool {
        match &self.config.sign {
            None => true,
            Some(kinds) => kinds.contains(&event.kind),
        }
    }

    fn can_encrypt(&self, recipient_pubkey: &PublicKey) -> bool {
        match &self.config.encrypt {
            None => true,
            Some(kinds) => kinds.contains(&event.kind),
        }
    }

    fn can_decrypt(&self, sender_pubkey: &PublicKey) -> bool {
        match &self.config.decrypt {
            None => true,
            Some(kinds) => kinds.contains(&event.kind),
        }
    }
}
