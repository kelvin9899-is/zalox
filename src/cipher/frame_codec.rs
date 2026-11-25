//! Binary 4-byte WebSocket framing and AES-GCM (16-byte Nonce & 16-byte AAD)
//! + Zlib/Deflate push-event decoder.

use std::io::Read;

use aes::{Aes128, Aes256};
use aes_gcm::{
    aead::{consts::U16, Aead, KeyInit, Payload},
    AesGcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bytes::{BufMut, Bytes, BytesMut};
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use serde_json::Value;

use crate::error::{ZaloxError, ZaloxResult};

type Aes128Gcm16 = AesGcm<Aes128, U16>;
type Aes256Gcm16 = AesGcm<Aes256, U16>;

/// 4-byte binary header prefixing every Zalo WebSocket packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireHeader {
    pub version: u8,
    pub command: u16,
    pub sub_command: u8,
}

impl WireHeader {
    pub const BYTE_LEN: usize = 4;

    /// Parses the 4-byte header `[version, cmd_lo, cmd_hi, sub_cmd]`.
    pub fn parse(raw: &[u8]) -> ZaloxResult<Self> {
        if raw.len() < Self::BYTE_LEN {
            return Err(ZaloxError::Frame(format!(
                "WebSocket packet too short ({} bytes, need >= 4)",
                raw.len()
            )));
        }
        Ok(Self {
            version: raw[0],
            command: u16::from_le_bytes([raw[1], raw[2]]),
            sub_command: raw[3],
        })
    }

    /// Writes the 4-byte header into a buffer.
    pub fn write_into(&self, dst: &mut BytesMut) {
        dst.put_u8(self.version);
        dst.put_u16_le(self.command);
        dst.put_u8(self.sub_command);
    }
}

/// Complete binary WebSocket frame consisting of a 4-byte `WireHeader` and JSON payload.
#[derive(Debug, Clone)]
pub struct WireFrame {
    pub header: WireHeader,
    pub payload: Value,
}

impl WireFrame {
    pub fn new(version: u8, command: u16, sub_command: u8, payload: Value) -> Self {
        Self {
            header: WireHeader {
                version,
                command,
                sub_command,
            },
            payload,
        }
    }

    /// Constructs the standard 3-minute keep-alive ping frame (`cmd = 2, sub_cmd = 1`).
    pub fn heartbeat(epoch_ms: u64) -> Self {
        Self::new(1, 2, 1, serde_json::json!({ "eventId": epoch_ms }))
    }

    /// Encodes the frame into raw bytes ready for WebSocket binary transmission.
    pub fn encode_bytes(&self) -> ZaloxResult<Bytes> {
        let json_bytes = serde_json::to_vec(&self.payload)?;
        let mut buf = BytesMut::with_capacity(WireHeader::BYTE_LEN + json_bytes.len());
        self.header.write_into(&mut buf);
        buf.extend_from_slice(&json_bytes);
        Ok(buf.freeze())
    }

    /// Decodes a raw binary WebSocket packet into `(WireHeader, Option<Value>)`.
    pub fn decode_bytes(packet: &[u8]) -> ZaloxResult<(WireHeader, Option<Value>)> {
        let header = WireHeader::parse(packet)?;
        let body = &packet[WireHeader::BYTE_LEN..];
        if body.is_empty() {
            return Ok((header, None));
        }
        let parsed: Value = serde_json::from_slice(body)?;
        Ok((header, Some(parsed)))
    }
}

/// Unpacks an inbound WebSocket JSON envelope containing `{ "encrypt": 0..=3, "data": "..." }`.
///
/// Encryption modes used by Zalo WebSocket streams:
/// - `0`: Plain UTF-8 JSON string in `data`.
/// - `1`: Base64 -> Zlib/Deflate compressed UTF-8 JSON.
/// - `2`: URL-escaped Base64 -> `[16B Nonce][16B AAD][Ciphertext+Tag]` AES-GCM -> Zlib/Deflate -> UTF-8 JSON.
/// - `3`: URL-escaped Base64 -> `[16B Nonce][16B AAD][Ciphertext+Tag]` AES-GCM -> Plain UTF-8 JSON.
pub fn unpack_push_envelope(
    envelope: &Value,
    ws_cipher_key_b64: Option<&str>,
) -> ZaloxResult<Value> {
    let encrypt_mode = envelope
        .get("encrypt")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ZaloxError::Frame("Missing numeric 'encrypt' field in WS envelope".into())
        })?;

    let raw_data = envelope
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| ZaloxError::Frame("Missing string 'data' field in WS envelope".into()))?;

    if encrypt_mode == 0 {
        return Ok(serde_json::from_str(raw_data)?);
    }
    if encrypt_mode > 3 {
        return Err(ZaloxError::Frame(format!(
            "Unsupported WS encryption mode: {encrypt_mode}"
        )));
    }

    let b64_text = if encrypt_mode == 1 {
        raw_data.to_owned()
    } else if raw_data.contains('%') {
        urlencoding::decode(raw_data)
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| raw_data.to_owned())
    } else {
        raw_data.to_owned()
    };

    let decoded_bytes = B64
        .decode(b64_text.trim())
        .map_err(|e| ZaloxError::Frame(format!("Invalid base64 in WS event payload: {e}")))?;

    let decrypted_stage = if encrypt_mode == 1 {
        decoded_bytes
    } else {
        let key_b64 = ws_cipher_key_b64
            .ok_or_else(|| ZaloxError::Cipher("Missing WebSocket session cipher key".into()))?;
        decrypt_ws_aes_gcm_16(&decoded_bytes, key_b64)?
    };

    let utf8_bytes = if encrypt_mode == 3 {
        decrypted_stage
    } else {
        decompress_payload(&decrypted_stage)?
    };

    let json_text = String::from_utf8(utf8_bytes)
        .map_err(|e| ZaloxError::Frame(format!("Decompressed WS event is not UTF-8: {e}")))?;
    Ok(serde_json::from_str(&json_text)?)
}

fn decrypt_ws_aes_gcm_16(buffer: &[u8], key_b64: &str) -> ZaloxResult<Vec<u8>> {
    // Layout: [0..16] = 16-byte IV/Nonce, [16..32] = 16-byte AAD, [32..] = Ciphertext + 16-byte GCM Tag (min 48 bytes)
    if buffer.len() < 48 {
        return Err(ZaloxError::Cipher(format!(
            "Encrypted WS buffer too short ({} bytes, expected >= 48)",
            buffer.len()
        )));
    }
    let key_raw = B64
        .decode(key_b64.trim())
        .map_err(|e| ZaloxError::Cipher(format!("Invalid base64 WS cipherKey: {e}")))?;

    let nonce = Nonce::<U16>::from_slice(&buffer[0..16]);
    let payload = Payload {
        msg: &buffer[32..],
        aad: &buffer[16..32],
    };

    match key_raw.len() {
        16 => {
            let aead = Aes128Gcm16::new_from_slice(&key_raw)
                .map_err(|e| ZaloxError::Cipher(e.to_string()))?;
            aead.decrypt(nonce, payload)
                .map_err(|_| ZaloxError::Cipher("AES-128-GCM authentication tag mismatch".into()))
        }
        32 => {
            let aead = Aes256Gcm16::new_from_slice(&key_raw)
                .map_err(|e| ZaloxError::Cipher(e.to_string()))?;
            aead.decrypt(nonce, payload)
                .map_err(|_| ZaloxError::Cipher("AES-256-GCM authentication tag mismatch".into()))
        }
        other => Err(ZaloxError::Cipher(format!(
            "Unsupported WS AES-GCM key length: {other} bytes"
        ))),
    }
}

fn decompress_payload(compressed: &[u8]) -> ZaloxResult<Vec<u8>> {
    if compressed.is_empty() {
        return Ok(Vec::new());
    }
    // Gzip magic header: 0x1f 0x8b
    if compressed.len() >= 2 && compressed[0] == 0x1f && compressed[1] == 0x8b {
        let mut out = Vec::new();
        GzDecoder::new(compressed)
            .read_to_end(&mut out)
            .map_err(|e| ZaloxError::Frame(format!("Gzip inflate failed: {e}")))?;
        return Ok(out);
    }

    // Try Zlib stream first (standard `pako.inflate` format starting with 0x78)
    let mut out = Vec::new();
    if ZlibDecoder::new(compressed).read_to_end(&mut out).is_ok() {
        return Ok(out);
    }

    // Fallback to raw Deflate stream
    out.clear();
    DeflateDecoder::new(compressed)
        .read_to_end(&mut out)
        .map_err(|e| ZaloxError::Frame(format!("Zlib/Deflate inflate failed: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{write::ZlibEncoder, Compression};

    use super::*;

    #[test]
    fn wire_frame_roundtrips_binary_header_and_json() {
        let frame = WireFrame::new(1, 521, 0, serde_json::json!({"ok": true}));
        let bytes = frame.encode_bytes().unwrap();
        assert_eq!(&bytes[..4], &[1, 9, 2, 0]); // 521 = 0x0209 -> LE [0x09, 0x02]

        let (hdr, body) = WireFrame::decode_bytes(&bytes).unwrap();
        assert_eq!(hdr.version, 1);
        assert_eq!(hdr.command, 521);
        assert_eq!(hdr.sub_command, 0);
        assert_eq!(body.unwrap()["ok"], true);
    }

    #[test]
    fn unpack_push_envelope_handles_aes_gcm_16_plus_zlib() {
        let raw_key = [0x24u8; 16];
        let key_b64 = B64.encode(raw_key);
        let original =
            serde_json::json!({"data": {"msgs": [{"msgId": "1001", "content": "Xin chào!"}]}});

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original.to_string().as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();

        let iv = [0x11u8; 16];
        let aad = [0x22u8; 16];
        let aead = Aes128Gcm16::new_from_slice(&raw_key).unwrap();
        let ciphertext = aead
            .encrypt(
                Nonce::<U16>::from_slice(&iv),
                Payload {
                    msg: &compressed,
                    aad: &aad,
                },
            )
            .unwrap();

        let mut packet = Vec::new();
        packet.extend_from_slice(&iv);
        packet.extend_from_slice(&aad);
        packet.extend_from_slice(&ciphertext);

        let env = serde_json::json!({
            "encrypt": 2,
            "data": urlencoding::encode(&B64.encode(&packet)).into_owned()
        });

        let unpacked = unpack_push_envelope(&env, Some(&key_b64)).unwrap();
        assert_eq!(unpacked["data"]["msgs"][0]["content"], "Xin chào!");
    }
}
