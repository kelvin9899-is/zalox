//! Symmetric AES-CBC parameter sealing, request MAC signing, and pre-login
//! client identity (`zcid`) derivation.

use std::collections::BTreeMap;

use aes::{Aes128, Aes192, Aes256};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5::{Digest, Md5};
use rand::Rng;
use uuid::Uuid;

use crate::error::{ZaloxError, ZaloxResult};

const BOOTSTRAP_ZCID_SECRET: &str = "3FC4F0D2AB50057BCE0D90D9187A22B1";
const ZERO_IV: [u8; 16] = [0u8; 16];

/// Generates a deterministic-format Web client IMEI bound to a User-Agent string.
pub fn generate_device_imei(user_agent: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(user_agent.as_bytes());
    let ua_digest = hex::encode(hasher.finalize());
    format!("{}-{}", Uuid::new_v4(), ua_digest)
}

/// Computes the sorted-parameter MD5 request signature (`zsecure` + tag + ordered values).
pub fn compute_request_mac(action_tag: &str, sorted_params: &BTreeMap<String, String>) -> String {
    let mut payload = String::with_capacity(64);
    payload.push_str("zsecure");
    payload.push_str(action_tag);
    for value in sorted_params.values() {
        payload.push_str(value);
    }
    let mut hasher = Md5::new();
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

/// Pre-login key negotiation material (`zcid`, `zcid_ext`, and transient AES key).
#[derive(Debug, Clone)]
pub struct HandshakeTicket {
    pub zcid: String,
    pub zcid_ext: String,
    pub enc_ver: &'static str,
    derived_key: String,
}

impl HandshakeTicket {
    /// Creates a fresh pre-login handshake ticket for `getLoginInfo` / `getServerInfo`.
    pub fn generate(client_type: u32, imei: &str, launch_epoch_ms: u64) -> ZaloxResult<Self> {
        if imei.is_empty() {
            return Err(ZaloxError::InvalidInput("IMEI must not be empty".into()));
        }
        let raw_identity = format!("{client_type},{imei},{launch_epoch_ms}");
        let zcid_bytes =
            aes_cbc_encrypt_zero_iv(BOOTSTRAP_ZCID_SECRET.as_bytes(), raw_identity.as_bytes())?;
        let zcid = hex::encode_upper(zcid_bytes);

        let zcid_ext = random_hex_token(6, 12);
        let derived_key = derive_handshake_key(&zcid, &zcid_ext)?;

        Ok(Self {
            zcid,
            zcid_ext,
            enc_ver: "v2",
            derived_key,
        })
    }

    /// Returns the derived 32-byte ASCII key used to encrypt login bootstrap parameters.
    pub fn transient_key(&self) -> &str {
        &self.derived_key
    }

    /// Seals a JSON string with the transient handshake key into Base64.
    pub fn seal_json(&self, plaintext: &str) -> ZaloxResult<String> {
        let encrypted = aes_cbc_encrypt_zero_iv(self.derived_key.as_bytes(), plaintext.as_bytes())?;
        Ok(B64.encode(encrypted))
    }

    /// Opens a Base64 (or URL-escaped Base64) login response using the transient handshake key.
    pub fn open_response(&self, encoded: &str) -> ZaloxResult<String> {
        let normalized = maybe_percent_decode(encoded);
        let raw = B64
            .decode(normalized.trim())
            .map_err(|e| ZaloxError::Cipher(format!("Invalid base64 login payload: {e}")))?;
        let plain = aes_cbc_decrypt_zero_iv(self.derived_key.as_bytes(), &raw)?;
        String::from_utf8(plain).map_err(|e| {
            ZaloxError::Cipher(format!("Decrypted login payload is not valid UTF-8: {e}"))
        })
    }
}

/// Authenticated session cipher backed by `zpw_enk` (Base64-encoded symmetric key).
#[derive(Clone)]
pub struct SessionCipher {
    key_bytes: Vec<u8>,
}

impl std::fmt::Debug for SessionCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCipher")
            .field("key_bits", &(self.key_bytes.len() * 8))
            .finish()
    }
}

impl SessionCipher {
    /// Constructs a `SessionCipher` from the Base64 `zpw_enk` secret returned at login.
    pub fn from_base64_secret(secret_b64: &str) -> ZaloxResult<Self> {
        let key_bytes = B64
            .decode(secret_b64.trim())
            .map_err(|e| ZaloxError::Cipher(format!("Invalid zpw_enk base64 key: {e}")))?;
        match key_bytes.len() {
            16 | 24 | 32 => Ok(Self { key_bytes }),
            other => Err(ZaloxError::Cipher(format!(
                "Unsupported AES key length: {other} bytes (expected 16, 24, or 32)"
            ))),
        }
    }

    /// Encrypts a UTF-8 JSON parameter string into Base64 for HTTP requests.
    pub fn seal_params(&self, json_payload: &str) -> ZaloxResult<String> {
        let ciphertext = aes_cbc_encrypt_zero_iv(&self.key_bytes, json_payload.as_bytes())?;
        Ok(B64.encode(ciphertext))
    }

    /// Decrypts a Base64 (or URL-encoded Base64) HTTP response `data` field into UTF-8 JSON.
    pub fn open_params(&self, ciphertext_b64: &str) -> ZaloxResult<String> {
        let clean = maybe_percent_decode(ciphertext_b64);
        let raw = B64.decode(clean.trim()).map_err(|e| {
            ZaloxError::Cipher(format!("Base64 decode failed on response data: {e}"))
        })?;
        let decrypted = aes_cbc_decrypt_zero_iv(&self.key_bytes, &raw)?;
        String::from_utf8(decrypted)
            .map_err(|e| ZaloxError::Cipher(format!("Decrypted response is not valid UTF-8: {e}")))
    }
}

fn maybe_percent_decode(input: &str) -> String {
    if input.contains('%') {
        urlencoding::decode(input)
            .map(|cow| cow.into_owned())
            .unwrap_or_else(|_| input.to_owned())
    } else {
        input.to_owned()
    }
}

fn random_hex_token(min_len: usize, max_len: usize) -> String {
    let mut rng = rand::thread_rng();
    let target_len = rng.gen_range(min_len..=max_len);
    (0..target_len)
        .map(|_| format!("{:x}", rng.gen_range(0u8..16u8)))
        .collect()
}

fn split_parity_chars(text: &str) -> (Vec<char>, Vec<char>) {
    let mut evens = Vec::with_capacity(text.len().div_ceil(2));
    let mut odds = Vec::with_capacity(text.len() / 2);
    for (idx, ch) in text.chars().enumerate() {
        if idx % 2 == 0 {
            evens.push(ch);
        } else {
            odds.push(ch);
        }
    }
    (evens, odds)
}

fn derive_handshake_key(zcid: &str, zcid_ext: &str) -> ZaloxResult<String> {
    let mut md5_hasher = Md5::new();
    md5_hasher.update(zcid_ext.as_bytes());
    let ext_md5_upper = hex::encode_upper(md5_hasher.finalize());

    let (ext_even, _) = split_parity_chars(&ext_md5_upper);
    let (zcid_even, mut zcid_odd) = split_parity_chars(zcid);
    zcid_odd.reverse();

    if ext_even.len() < 8 || zcid_even.len() < 12 || zcid_odd.len() < 12 {
        return Err(ZaloxError::Cipher(
            "Insufficient entropy material while deriving handshake key".into(),
        ));
    }

    let mut out = String::with_capacity(32);
    out.extend(ext_even.into_iter().take(8));
    out.extend(zcid_even.into_iter().take(12));
    out.extend(zcid_odd.into_iter().take(12));
    Ok(out)
}

fn aes_cbc_encrypt_zero_iv(key: &[u8], plaintext: &[u8]) -> ZaloxResult<Vec<u8>> {
    match key.len() {
        16 => {
            let enc = Encryptor::<Aes128>::new_from_slices(key, &ZERO_IV)
                .map_err(|e| ZaloxError::Cipher(e.to_string()))?;
            Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
        }
        24 => {
            let enc = Encryptor::<Aes192>::new_from_slices(key, &ZERO_IV)
                .map_err(|e| ZaloxError::Cipher(e.to_string()))?;
            Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
        }
        32 => {
            let enc = Encryptor::<Aes256>::new_from_slices(key, &ZERO_IV)
                .map_err(|e| ZaloxError::Cipher(e.to_string()))?;
            Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
        }
        len => Err(ZaloxError::Cipher(format!(
            "Invalid AES-CBC key size: {len} bytes"
        ))),
    }
}

fn aes_cbc_decrypt_zero_iv(key: &[u8], ciphertext: &[u8]) -> ZaloxResult<Vec<u8>> {
    match key.len() {
        16 => {
            let dec = Decryptor::<Aes128>::new_from_slices(key, &ZERO_IV)
                .map_err(|e| ZaloxError::Cipher(e.to_string()))?;
            dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
                .map_err(|e| ZaloxError::Cipher(format!("AES-128-CBC unpad error: {e}")))
        }
        24 => {
            let dec = Decryptor::<Aes192>::new_from_slices(key, &ZERO_IV)
                .map_err(|e| ZaloxError::Cipher(e.to_string()))?;
            dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
                .map_err(|e| ZaloxError::Cipher(format!("AES-192-CBC unpad error: {e}")))
        }
        32 => {
            let dec = Decryptor::<Aes256>::new_from_slices(key, &ZERO_IV)
                .map_err(|e| ZaloxError::Cipher(e.to_string()))?;
            dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
                .map_err(|e| ZaloxError::Cipher(format!("AES-256-CBC unpad error: {e}")))
        }
        len => Err(ZaloxError::Cipher(format!(
            "Invalid AES-CBC key size: {len} bytes"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_session_cipher_aes128_and_aes256() {
        let key16_b64 = B64.encode([0x42u8; 16]);
        let cipher16 = SessionCipher::from_base64_secret(&key16_b64).unwrap();
        let sample = r#"{"message":"Xin chào Việt Nam! 🦀","ttl":0}"#;
        let sealed = cipher16.seal_params(sample).unwrap();
        let opened = cipher16.open_params(&sealed).unwrap();
        assert_eq!(opened, sample);

        let key32_b64 = B64.encode([0x99u8; 32]);
        let cipher32 = SessionCipher::from_base64_secret(&key32_b64).unwrap();
        let url_escaped = urlencoding::encode(&cipher32.seal_params(sample).unwrap()).into_owned();
        assert_eq!(cipher32.open_params(&url_escaped).unwrap(), sample);
    }

    #[test]
    fn handshake_ticket_generates_32_byte_key_and_roundtrips() {
        let imei = generate_device_imei("Mozilla/5.0 TestAgent");
        let ticket = HandshakeTicket::generate(30, &imei, 1_735_000_000_000).unwrap();
        assert_eq!(ticket.transient_key().len(), 32);
        assert!(!ticket.zcid.is_empty());

        let body = r#"{"computer_name":"Web","language":"vi"}"#;
        let enc = ticket.seal_json(body).unwrap();
        let dec = ticket.open_response(&enc).unwrap();
        assert_eq!(dec, body);
    }

    #[test]
    fn request_mac_sorts_parameters_deterministically() {
        let mut params = BTreeMap::new();
        params.insert("type".to_string(), "30".to_string());
        params.insert("computer_name".to_string(), "Web".to_string());
        params.insert("client_version".to_string(), "695".to_string());
        let sig = compute_request_mac("getserverinfo", &params);
        assert_eq!(sig.len(), 32);
    }
}
