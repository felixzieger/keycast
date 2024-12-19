pub mod aws_key_manager;
pub mod file_key_manager;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("Key manager not initialized")]
    NotInitialized,
}

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
}

#[async_trait]
pub trait KeyManager: Send + Sync {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError>;
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError>;
}
