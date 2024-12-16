#![allow(unused)]

use super::{EncryptionError, KeyManager};
use async_trait::async_trait;

pub struct AwsKeyManager {
    // Add AWS KMS client here
}

impl AwsKeyManager {
    pub async fn new() -> Result<Self, EncryptionError> {
        // Initialize AWS KMS client here
        todo!("Implement AWS KMS client initialization")
    }
}

#[async_trait]
impl KeyManager for AwsKeyManager {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        todo!("Implement AWS KMS encryption")
    }

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        todo!("Implement AWS KMS decryption")
    }
}
