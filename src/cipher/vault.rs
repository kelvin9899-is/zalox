//! Password-protected local session vault (`ZLX1` format: PBKDF2-HMAC-SHA256 + AES-256-GCM)
//! so Zalo cookies and device credentials never sit in plaintext on disk.

use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use sha2::Sha256;

use crate::error::{ZaloxError, ZaloxResult};

const VAULT_MAGIC: &[u8; 4] = b"ZLX1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const PBKDF2_ROUNDS: u32 = 100_000;

/// Encrypts and decrypts arbitrary serializable session bundles using a passphrase.
pub struct SessionVault;

impl SessionVault {
    /// Seals a serializable struct into a `ZLX1` binary blob protected by `passphrase`.
    pub fn seal_bytes<T: Serialize>(value: &T, passphrase: &str) -> ZaloxResult<Vec<u8>> {
        if passphrase.is_empty() {
            return Err(ZaloxError::Vault("Vault passphrase cannot be empty".into()));
        }
        let plaintext = serde_json::to_vec(value)?;

        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce_bytes);

        let key = derive_vault_key(passphrase, &salt);
        let aead = Aes256Gcm::new_from_slice(&key).map_err(|e| ZaloxError::Vault(e.to_string()))?;
        let ciphertext = aead
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|_| ZaloxError::Vault("Vault AES-256-GCM encryption failed".into()))?;

        let mut blob =
            Vec::with_capacity(VAULT_MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(VAULT_MAGIC);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    /// Opens and deserializes a `ZLX1` binary blob using `passphrase`.
    pub fn open_bytes<T: DeserializeOwned>(blob: &[u8], passphrase: &str) -> ZaloxResult<T> {
        const HEADER_LEN: usize = 4 + SALT_LEN + NONCE_LEN;
        if blob.len() < HEADER_LEN + 16 {
            return Err(ZaloxError::Vault(
                "Vault file is truncated or corrupted".into(),
            ));
        }
        if &blob[0..4] != VAULT_MAGIC {
            return Err(ZaloxError::Vault(
                "Unrecognized vault magic header (expected ZLX1)".into(),
            ));
        }

        let salt = &blob[4..4 + SALT_LEN];
        let nonce_bytes = &blob[4 + SALT_LEN..HEADER_LEN];
        let ciphertext = &blob[HEADER_LEN..];

        let key = derive_vault_key(passphrase, salt);
        let aead = Aes256Gcm::new_from_slice(&key).map_err(|e| ZaloxError::Vault(e.to_string()))?;
        let plaintext = aead
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| ZaloxError::Vault("Incorrect vault passphrase or tampered file".into()))?;

        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Saves an encrypted session vault atomically to disk.
    pub async fn save_file<T: Serialize>(
        path: impl AsRef<Path>,
        value: &T,
        passphrase: &str,
    ) -> ZaloxResult<()> {
        let bytes = Self::seal_bytes(value, passphrase)?;
        tokio::fs::write(path, bytes).await?;
        Ok(())
    }

    /// Loads and decrypts an encrypted session vault from disk.
    pub async fn load_file<T: DeserializeOwned>(
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> ZaloxResult<T> {
        let bytes = tokio::fs::read(path).await?;
        Self::open_bytes(&bytes, passphrase)
    }
}

fn derive_vault_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, PBKDF2_ROUNDS, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_roundtrip_and_wrong_password_rejection() {
        let data = serde_json::json!({"imei": "abc-123", "secret": "top-secret"});
        let blob = SessionVault::seal_bytes(&data, "correct-horse-battery").unwrap();
        let restored: serde_json::Value =
            SessionVault::open_bytes(&blob, "correct-horse-battery").unwrap();
        assert_eq!(restored, data);

        let bad = SessionVault::open_bytes::<serde_json::Value>(&blob, "wrong-pass");
        assert!(bad.is_err());
    }
}
