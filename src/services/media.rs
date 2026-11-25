//! Chunked media & document uploader and photo/file message dispatcher
//! powered by Pure-Rust image header probing (zero `sharp`/`libvips` dependency).

use std::{path::Path, time::Duration};

use md5::{Digest, Md5};
use reqwest::multipart::{Form, Part};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::time::timeout;

use crate::{
    error::{ZaloxError, ZaloxResult},
    services::{image_probe::probe_image_dimensions, messaging::MessageReceipt},
    session::{now_epoch_ms, ZaloxSession},
    types::Peer,
};

/// Input media payload loaded from disk or generated in-memory (e.g., dynamic VietQR PNG).
#[derive(Debug, Clone)]
pub struct MediaSource {
    pub file_name: String,
    pub bytes: Vec<u8>,
}

impl MediaSource {
    /// Wraps an in-memory byte buffer (ideal for generated QR images or PDFs).
    pub fn from_bytes(file_name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            file_name: file_name.into(),
            bytes,
        }
    }

    /// Reads a file asynchronously from disk.
    pub async fn from_path(path: impl AsRef<Path>) -> ZaloxResult<Self> {
        let p = path.as_ref();
        let file_name = p
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                ZaloxError::InvalidInput("Media path has no valid UTF-8 file name".into())
            })?
            .to_owned();
        let bytes = tokio::fs::read(p).await?;
        Ok(Self { file_name, bytes })
    }

    pub fn extension_lower(&self) -> String {
        Path::new(&self.file_name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
    }
}

/// Completed upload descriptor ready to be dispatched in a chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UploadedAttachment {
    Photo {
        photo_id: String,
        client_file_id: i64,
        normal_url: String,
        hd_url: String,
        thumb_url: String,
        width: u32,
        height: u32,
        total_size: usize,
    },
    DocumentOrVideo {
        is_video: bool,
        file_id: String,
        file_url: String,
        client_file_id: i64,
        file_name: String,
        checksum_md5: String,
        total_size: usize,
    },
}

#[derive(Debug, Deserialize)]
struct RawUploadChunkResp {
    #[serde(default)]
    #[serde(rename = "clientFileId")]
    client_file_id: i64,
    #[serde(rename = "fileId")]
    file_id: Option<Value>,
    #[serde(rename = "photoId")]
    photo_id: Option<Value>,
    #[serde(rename = "normalUrl")]
    normal_url: Option<String>,
    #[serde(rename = "hdUrl")]
    hd_url: Option<String>,
    #[serde(rename = "thumbUrl")]
    thumb_url: Option<String>,
}

/// Domain facade for uploading and sending images, videos, and arbitrary documents.
#[derive(Clone)]
pub struct MediaService {
    session: ZaloxSession,
}

impl MediaService {
    pub(crate) fn new(session: ZaloxSession) -> Self {
        Self { session }
    }

    /// Uploads `source` in chunks to Zalo's file servers for `peer`.
    ///
    /// Note: Uploading `mp4` or generic documents requires an active `subscribe_events()`
    /// WebSocket listener so Zalo's async `file_done` callback can be received.
    pub async fn upload(
        &self,
        peer: &Peer,
        source: &MediaSource,
    ) -> ZaloxResult<UploadedAttachment> {
        if source.bytes.is_empty() {
            return Err(ZaloxError::InvalidInput(
                "Cannot upload an empty 0-byte file".into(),
            ));
        }

        let limits = &self.session.core.settings.features.sharefile;
        let max_bytes = limits.max_size_share_file_v3.max(25) * 1024 * 1024;
        if source.bytes.len() > max_bytes {
            return Err(ZaloxError::Media(format!(
                "File '{}' ({} bytes) exceeds maximum allowed size ({max_bytes} bytes)",
                source.file_name,
                source.bytes.len()
            )));
        }

        let ext = source.extension_lower();
        if limits
            .restricted_ext_file
            .iter()
            .any(|r| r.eq_ignore_ascii_case(&ext))
        {
            return Err(ZaloxError::Media(format!(
                "File extension '.{ext}' is restricted by Zalo server policy"
            )));
        }

        let is_photo = matches!(ext.as_str(), "jpg" | "jpeg" | "png" | "webp");
        let is_video = ext == "mp4";
        let geometry = if is_photo {
            Some(probe_image_dimensions(&source.bytes)?)
        } else {
            None
        };

        let chunk_size = limits.chunk_size_file.max(512 * 1024);
        let total_chunks = source.bytes.len().div_ceil(chunk_size);
        let client_id = now_epoch_ms();
        let is_group = peer.is_group();

        let route_scope = if is_group { "group" } else { "message" };
        let upload_subpath = if is_photo {
            "photo_original/upload"
        } else {
            "asyncfile/upload"
        };
        let type_param = if is_group { "11" } else { "2" };
        let base_url = format!(
            "{}/api/{route_scope}/{upload_subpath}",
            self.session.core.services.file_base()
        );

        let mut last_resp: Option<RawUploadChunkResp> = None;

        for (idx, chunk) in source.bytes.chunks(chunk_size).enumerate() {
            let chunk_id = idx + 1;
            let mut params = Map::new();
            params.insert(
                if is_group { "grid" } else { "toid" }.into(),
                Value::String(peer.id.clone()),
            );
            params.insert("totalChunk".into(), json!(total_chunks));
            params.insert("fileName".into(), Value::String(source.file_name.clone()));
            params.insert("clientId".into(), json!(client_id));
            params.insert("totalSize".into(), json!(source.bytes.len()));
            params.insert("imei".into(), Value::String(self.session.core.imei.clone()));
            params.insert("isE2EE".into(), json!(0));
            params.insert("jxl".into(), json!(0));
            params.insert("chunkId".into(), json!(chunk_id));

            let sealed = self
                .session
                .core
                .cipher
                .seal_params(&Value::Object(params).to_string())?;

            let endpoint = self.session.core.gateway.build_endpoint_url(
                &base_url,
                &[("type", type_param.into()), ("params", sealed)],
                true,
            )?;

            let part = Part::bytes(chunk.to_vec())
                .file_name(source.file_name.clone())
                .mime_str("application/octet-stream")?;
            let form = Form::new().part("chunkContent", part);

            self.session.core.gateway.pacer().acquire().await;
            let http_resp = self
                .session
                .core
                .gateway
                .client()
                .post(endpoint)
                .headers(self.session.core.gateway.standard_headers())
                .multipart(form)
                .send()
                .await?;

            let parsed: RawUploadChunkResp = self
                .session
                .core
                .gateway
                .decode_zalo_envelope(http_resp, Some(&self.session.core.cipher))
                .await?;
            last_resp = Some(parsed);
        }

        let final_chunk = last_resp
            .ok_or_else(|| ZaloxError::Media("Upload completed 0 chunks unexpectedly".into()))?;

        if let Some(geo) = geometry {
            let photo_id = json_id_to_string(final_chunk.photo_id)
                .ok_or_else(|| ZaloxError::Media("Photo upload response missing photoId".into()))?;
            return Ok(UploadedAttachment::Photo {
                photo_id,
                client_file_id: final_chunk.client_file_id,
                normal_url: final_chunk.normal_url.unwrap_or_default(),
                hd_url: final_chunk.hd_url.unwrap_or_default(),
                thumb_url: final_chunk.thumb_url.unwrap_or_default(),
                width: geo.width,
                height: geo.height,
                total_size: source.bytes.len(),
            });
        }

        let file_id = json_id_to_string(final_chunk.file_id)
            .ok_or_else(|| ZaloxError::Media("Async file upload response missing fileId".into()))?;

        let waiter = self.session.register_upload_waiter(file_id.clone()).await;
        let ready = timeout(Duration::from_secs(60), waiter)
            .await
            .map_err(|_| {
                ZaloxError::Media(
                    "Timed out waiting for WebSocket `file_done` event (ensure `subscribe_events()` is active)"
                        .into(),
                )
            })?
            .map_err(|_| ZaloxError::Media("Upload completion channel closed prematurely".into()))?;

        let mut md5_hasher = Md5::new();
        md5_hasher.update(&source.bytes);
        let checksum_md5 = hex::encode(md5_hasher.finalize());

        Ok(UploadedAttachment::DocumentOrVideo {
            is_video,
            file_id: ready.file_id,
            file_url: ready.file_url,
            client_file_id: final_chunk.client_file_id,
            file_name: source.file_name.clone(),
            checksum_md5,
            total_size: source.bytes.len(),
        })
    }

    /// Uploads and immediately sends a photo (`png`, `jpg`, `webp`) with an optional caption.
    /// Works standalone over HTTP without requiring an active WebSocket listener!
    pub async fn send_photo(
        &self,
        peer: Peer,
        source: MediaSource,
        caption: &str,
        ttl_ms: u64,
    ) -> ZaloxResult<MessageReceipt> {
        let uploaded = self.upload(&peer, &source).await?;
        let UploadedAttachment::Photo {
            photo_id,
            normal_url,
            hd_url,
            thumb_url,
            width,
            height,
            total_size,
            ..
        } = uploaded
        else {
            return Err(ZaloxError::InvalidInput(
                "send_photo expects a PNG, JPEG, or WebP image (use send_file for documents/videos)".into(),
            ));
        };

        let is_group = peer.is_group();
        let mut params = Map::new();
        params.insert("photoId".into(), Value::String(photo_id));
        params.insert("clientId".into(), Value::String(now_epoch_ms().to_string()));
        params.insert("desc".into(), Value::String(caption.to_owned()));
        params.insert("width".into(), json!(width));
        params.insert("height".into(), json!(height));
        params.insert("rawUrl".into(), Value::String(normal_url.clone()));
        params.insert("hdUrl".into(), Value::String(hd_url));
        params.insert("thumbUrl".into(), Value::String(thumb_url));
        params.insert("hdSize".into(), Value::String(total_size.to_string()));
        params.insert("zsource".into(), json!(-1));
        params.insert("ttl".into(), json!(ttl_ms));
        params.insert(
            "jcp".into(),
            Value::String(r#"{"convertible":"jxl"}"#.into()),
        );

        let scope = if is_group {
            params.insert("grid".into(), Value::String(peer.id));
            params.insert("oriUrl".into(), Value::String(normal_url));
            "group"
        } else {
            params.insert("toid".into(), Value::String(peer.id));
            params.insert("normalUrl".into(), Value::String(normal_url));
            "message"
        };

        let base = format!(
            "{}/api/{scope}/photo_original/send",
            self.session.core.services.file_base()
        );
        let url =
            self.session
                .core
                .gateway
                .build_endpoint_url(&base, &[("nretry", "0".into())], true)?;

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &Value::Object(params), true)
            .await
    }

    /// Uploads and sends a document or MP4 video to `peer` (requires active `subscribe_events()`).
    pub async fn send_file(
        &self,
        peer: Peer,
        source: MediaSource,
        ttl_ms: u64,
    ) -> ZaloxResult<MessageReceipt> {
        let ext = source.extension_lower();
        let uploaded = self.upload(&peer, &source).await?;
        let UploadedAttachment::DocumentOrVideo {
            file_id,
            file_url,
            client_file_id,
            file_name,
            checksum_md5,
            total_size,
            ..
        } = uploaded
        else {
            return self.send_photo(peer, source, "", ttl_ms).await;
        };

        let is_group = peer.is_group();
        let mut params = Map::new();
        params.insert("fileId".into(), Value::String(file_id));
        params.insert("checksum".into(), Value::String(checksum_md5));
        params.insert("checksumSha".into(), Value::String(String::new()));
        params.insert("extention".into(), Value::String(ext));
        params.insert("totalSize".into(), json!(total_size));
        params.insert("fileName".into(), Value::String(file_name));
        params.insert("clientId".into(), json!(client_file_id));
        params.insert("fType".into(), json!(1));
        params.insert("fileCount".into(), json!(0));
        params.insert("fdata".into(), Value::String("{}".into()));
        params.insert("fileUrl".into(), Value::String(file_url));
        params.insert("zsource".into(), json!(-1));
        params.insert("ttl".into(), json!(ttl_ms));

        let scope = if is_group {
            params.insert("grid".into(), Value::String(peer.id));
            "group"
        } else {
            params.insert("toid".into(), Value::String(peer.id));
            "message"
        };

        let base = format!(
            "{}/api/{scope}/asyncfile/msg",
            self.session.core.services.file_base()
        );
        let url =
            self.session
                .core
                .gateway
                .build_endpoint_url(&base, &[("nretry", "0".into())], true)?;

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &Value::Object(params), true)
            .await
    }
}

fn json_id_to_string(val: Option<Value>) -> Option<String> {
    match val {
        Some(Value::String(s)) if !s.is_empty() && s != "-1" => Some(s),
        Some(Value::Number(n)) => {
            let s = n.to_string();
            if s != "-1" {
                Some(s)
            } else {
                None
            }
        }
        _ => None,
    }
}
