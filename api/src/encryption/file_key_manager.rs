use super::{EncryptionError, KeyManager};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::Rng;
use std::env;
use std::path::PathBuf;

pub struct FileKeyManager {
    cipher: Aes256Gcm,
}

impl FileKeyManager {
    pub fn new() -> Result<Self, EncryptionError> {
        let key = Self::load_key()?;
        let cipher = Aes256Gcm::new(&key.into());
        Ok(Self { cipher })
    }

    fn load_key() -> Result<[u8; 32], EncryptionError> {
        let key_path = PathBuf::from(
            env::var("MASTER_KEY")
                .map_err(|_| EncryptionError::Configuration("MASTER_KEY not set".to_string()))?,
        );

        let key_str = std::fs::read_to_string(key_path)
            .map_err(|e| EncryptionError::Configuration(e.to_string()))?;

        BASE64
            .decode(key_str.trim())
            .map_err(|e| EncryptionError::Configuration(e.to_string()))?
            .try_into()
            .map_err(|_| EncryptionError::Configuration("Invalid key length".to_string()))
    }
}

#[async_trait]
impl KeyManager for FileKeyManager {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let nonce = rand::thread_rng().gen::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| EncryptionError::Encryption(e.to_string()))?;

        // Combine nonce and ciphertext
        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if ciphertext.len() < 12 {
            return Err(EncryptionError::Decryption(
                "Ciphertext too short".to_string(),
            ));
        }

        let (nonce, encrypted) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce);

        self.cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| EncryptionError::Decryption(e.to_string()))
    }
}
