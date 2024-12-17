use crate::models::permission::PolicyPermission;
use nostr_sdk::Event;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ContentFilterConfig {
    pub blocked_words: Option<Vec<String>>,
}

impl Default for ContentFilterConfig {
    fn default() -> Self {
        Self {
            blocked_words: None,
        }
    }
}

pub struct ContentFilter {
    config: ContentFilterConfig,
}

impl ContentFilter {
    pub fn new(config: ContentFilterConfig) -> Self {
        Self { config }
    }
}

impl PolicyPermission for ContentFilter {
    fn identifier() -> &'static str {
        "content_filter"
    }

    fn can_sign(&self, event: &Event) -> bool {
        match &self.config.blocked_words {
            None => true,
            Some(words) => !words.iter().any(|word| event.content.contains(word)),
        }
    }

    fn can_encrypt(&self, recipient_pubkey: &PublicKey) -> bool {
        match &self.config.blocked_words {
            None => true,
            Some(words) => !words.iter().any(|word| event.content.contains(word)),
        }
    }

    // We can't know what is in the content of the event, so we always allow decryption
    fn can_decrypt(&self, sender_pubkey: &PublicKey) -> bool {
        true
    }
}
