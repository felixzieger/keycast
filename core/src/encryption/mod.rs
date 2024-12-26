pub mod aws_key_manager;
pub mod file_key_manager;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("Failed to load key")]
    LoadKey(String),
    #[error("Failed to encrypt")]
    Encrypt(String),
    #[error("Failed to decrypt")]
    Decrypt(String),
    #[error("Failed to generate master key")]
    GenerateMasterKey(String),
}

#[async_trait]
pub trait KeyManager: Send + Sync {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError>;
    async fn decrypt(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError>;
}
