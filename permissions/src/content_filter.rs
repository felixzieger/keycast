use async_trait::async_trait;
use keycast_core::traits::CustomPermission;
use nostr_sdk::{Event, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ContentFilterConfig {
    pub blocked_words: Option<Vec<String>>,
}

impl From<ContentFilterConfig> for serde_json::Value {
    fn from(config: ContentFilterConfig) -> Self {
        serde_json::to_value(config).unwrap()
    }
}

pub struct ContentFilter {
    config: ContentFilterConfig,
}

#[async_trait]
impl CustomPermission for ContentFilter {
    fn identifier(&self) -> &'static str {
        "content_filter"
    }

    fn config(&self) -> serde_json::Value {
        self.config.clone().into()
    }

    async fn can_sign(&self, event: &Event) -> bool {
        match &self.config.blocked_words {
            None => true,
            Some(words) => !words.iter().any(|word| event.content.contains(word)),
        }
    }

    async fn can_encrypt(&self, event: &Event, _recipient_pubkey: &PublicKey) -> bool {
        match &self.config.blocked_words {
            None => true,
            Some(words) => !words.iter().any(|word| event.content.contains(word)),
        }
    }

    // We can't know what is in the content of the event, so we always allow decryption
    async fn can_decrypt(&self, _event: &Event, _sender_pubkey: &PublicKey) -> bool {
        true
    }
}

#[test]
fn test_default() {
    let config = ContentFilterConfig::default();
    assert!(config.blocked_words.is_none());
}
