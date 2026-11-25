//! Serializable credential bundles compatible with both encrypted `SessionVault`
//! files and browser cookie-exporter extensions.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    cipher::{generate_device_imei, SessionVault},
    error::{ZaloxError, ZaloxResult},
    transport::http::DEFAULT_USER_AGENT,
};

/// Single HTTP cookie entry supporting both standard (`name`) and `tough-cookie` (`key`) JSON schemas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieRecord {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub value: String,
    #[serde(default = "default_domain")]
    pub domain: String,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default = "default_true")]
    pub secure: bool,
    #[serde(default)]
    pub http_only: bool,
}

fn default_domain() -> String {
    "chat.zalo.me".into()
}

fn default_path() -> String {
    "/".into()
}

fn default_true() -> bool {
    true
}

impl CookieRecord {
    pub fn effective_name(&self) -> &str {
        if !self.name.is_empty() {
            &self.name
        } else {
            self.key.as_deref().unwrap_or_default()
        }
    }

    pub fn effective_path(&self) -> &str {
        if self.path.is_empty() {
            "/"
        } else {
            &self.path
        }
    }
}

/// Flexible cookie container accepting either `[CookieRecord, ...]` or `{ "cookies": [...] }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CookieInput {
    List(Vec<CookieRecord>),
    Wrapped { cookies: Vec<CookieRecord> },
}

impl CookieInput {
    pub fn into_vec(self) -> Vec<CookieRecord> {
        match self {
            Self::List(v) => v,
            Self::Wrapped { cookies } => cookies,
        }
    }

    pub fn as_slice(&self) -> &[CookieRecord] {
        match self {
            Self::List(v) => v,
            Self::Wrapped { cookies } => cookies,
        }
    }
}

/// Complete portable login bundle for resuming a personal Zalo session without re-scanning QR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCredentials {
    pub imei: String,
    pub cookies: CookieInput,
    #[serde(default = "default_ua")]
    pub user_agent: String,
    #[serde(default = "default_lang")]
    pub language: String,
}

fn default_ua() -> String {
    DEFAULT_USER_AGENT.into()
}

fn default_lang() -> String {
    "vi".into()
}

impl AuthCredentials {
    /// Creates a new credential bundle, automatically generating a valid Web IMEI if empty.
    pub fn new(
        imei: impl Into<String>,
        cookies: Vec<CookieRecord>,
        user_agent: impl Into<String>,
    ) -> Self {
        let ua = user_agent.into();
        let raw_imei = imei.into();
        let final_imei = if raw_imei.trim().is_empty() {
            generate_device_imei(&ua)
        } else {
            raw_imei
        };
        Self {
            imei: final_imei,
            cookies: CookieInput::List(cookies),
            user_agent: ua,
            language: "vi".into(),
        }
    }

    pub fn validate(&self) -> ZaloxResult<()> {
        if self.imei.trim().is_empty() {
            return Err(ZaloxError::InvalidInput(
                "Credential 'imei' is empty".into(),
            ));
        }
        if self.cookies.as_slice().is_empty() {
            return Err(ZaloxError::InvalidInput(
                "Credential 'cookies' list is empty".into(),
            ));
        }
        if self.user_agent.trim().is_empty() {
            return Err(ZaloxError::InvalidInput(
                "Credential 'user_agent' is empty".into(),
            ));
        }
        Ok(())
    }

    /// Saves credentials encrypted on disk using `SessionVault` (`ZLX1` AES-256-GCM).
    pub async fn save_encrypted(
        &self,
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> ZaloxResult<()> {
        SessionVault::save_file(path, self, passphrase).await
    }

    /// Loads credentials from an encrypted `SessionVault` file.
    pub async fn load_encrypted(path: impl AsRef<Path>, passphrase: &str) -> ZaloxResult<Self> {
        SessionVault::load_file(path, passphrase).await
    }

    /// Saves credentials as formatted JSON (useful for debugging or external tooling).
    pub async fn save_json(&self, path: impl AsRef<Path>) -> ZaloxResult<()> {
        let text = serde_json::to_string_pretty(self)?;
        tokio::fs::write(path, text).await?;
        Ok(())
    }

    /// Loads credentials from a JSON file.
    pub async fn load_json(path: impl AsRef<Path>) -> ZaloxResult<Self> {
        let text = tokio::fs::read_to_string(path).await?;
        Ok(serde_json::from_str(&text)?)
    }
}
