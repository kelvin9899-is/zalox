//! Unified error types for the `zalox` SDK.

use thiserror::Error;

/// Convenient result alias used across all `zalox` modules.
pub type ZaloxResult<T> = Result<T, ZaloxError>;

/// Categorized errors produced by `zalox` operations.
#[derive(Debug, Error)]
pub enum ZaloxError {
    #[error("HTTP transport failure: {0}")]
    Http(#[from] reqwest::Error),

    #[error("WebSocket transport failure: {0}")]
    WebSocket(#[from] Box<tokio_tungstenite::tungstenite::Error>),

    #[error("JSON serialization/parsing failure: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptographic operation failed: {0}")]
    Cipher(String),

    #[error("Frame protocol error: {0}")]
    Frame(String),

    #[error("QR authentication aborted or failed: {0}")]
    QrAuth(String),

    #[error("QR login was declined on mobile device")]
    QrDeclined,

    #[error("Session authentication error: {0}")]
    Auth(String),

    #[error("Zalo remote service returned error (code {code:?}): {detail}")]
    RemoteApi { code: Option<i64>, detail: String },

    #[error("Encrypted vault error: {0}")]
    Vault(String),

    #[error("Media inspection or upload error: {0}")]
    Media(String),

    #[error("Invalid argument: {0}")]
    InvalidInput(String),

    #[error("Realtime listener is not active or timed out: {0}")]
    Realtime(String),

    #[error("Ecosystem integration error: {0}")]
    Ecosystem(String),
}

impl From<tokio_tungstenite::tungstenite::Error> for ZaloxError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocket(Box::new(err))
    }
}
