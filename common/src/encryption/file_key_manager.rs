use super::{KeyManager, KeyManagerError};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::Rng;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

pub struct FileKeyManager {
    cipher: Aes256Gcm,
}

impl FileKeyManager {
    pub fn new() -> Result<Self, KeyManagerError> {
        let key = Self::load_key()?;
        let cipher = Aes256Gcm::new(&key.into());
        Ok(Self { cipher })
    }

    fn load_key() -> Result<[u8; 32], KeyManagerError> {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Failed to get parent directory")
            .to_path_buf();
        let key_path = project_root.join("master.key");

        let key_str = std::fs::read_to_string(key_path)
            .map_err(|e| KeyManagerError::LoadKey(e.to_string()))?;

        BASE64
            .decode(key_str.trim())
            .map_err(|e| KeyManagerError::LoadKey(e.to_string()))?
            .try_into()
            .map_err(|_| KeyManagerError::LoadKey("Invalid key length".to_string()))
    }
}

#[async_trait]
impl KeyManager for FileKeyManager {
    async fn encrypt<'a>(&'a self, plaintext: &'a [u8]) -> Result<Vec<u8>, KeyManagerError> {
        let nonce = rand::thread_rng().gen::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| KeyManagerError::Encrypt(e.to_string()))?;

        // Combine nonce and ciphertext
        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    async fn decrypt<'a>(&'a self, ciphertext: &'a [u8]) -> Result<Vec<u8>, KeyManagerError> {
        if ciphertext.len() < 12 {
            return Err(KeyManagerError::Decrypt("Ciphertext too short".to_string()));
        }

        let (nonce, encrypted) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce);

        self.cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| KeyManagerError::Decrypt(e.to_string()))
    }

    async fn generate_master_key(&self) -> Result<(), KeyManagerError> {
        let key: [u8; 32] = rand::thread_rng().gen();
        let encoded = BASE64.encode(key);

        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Failed to get parent directory")
            .to_path_buf();
        let key_path = project_root.join("master.key");

        let mut file = File::create(&key_path)
            .map_err(|e| KeyManagerError::GenerateMasterKey(e.to_string()))?;
        file.write_all(encoded.as_bytes())
            .map_err(|e| KeyManagerError::GenerateMasterKey(e.to_string()))?;

        println!("Saved new master key to {}", key_path.display());
        Ok(())
    }
}
