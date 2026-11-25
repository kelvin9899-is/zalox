//! Shared domain primitives, peer addressing, and server topology models.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Conversation kind: direct 1-on-1 user chat or multi-member group thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChannelKind {
    Direct = 0,
    Group = 1,
}

/// Strongly-typed conversation target (`Peer::user("...")` or `Peer::group("...")`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub kind: ChannelKind,
}

impl Peer {
    /// Creates a direct 1-on-1 user peer target.
    pub fn user(uid: impl Into<String>) -> Self {
        Self {
            id: uid.into(),
            kind: ChannelKind::Direct,
        }
    }

    /// Creates a group conversation peer target.
    pub fn group(group_id: impl Into<String>) -> Self {
        Self {
            id: group_id.into(),
            kind: ChannelKind::Group,
        }
    }

    pub fn is_group(&self) -> bool {
        self.kind == ChannelKind::Group
    }
}

/// Avatar resolution preset requested in profile/contact lookups.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum AvatarPreset {
    #[default]
    Small = 120,
    Medium = 240,
    Large = 300,
}

/// Dynamic service endpoint map returned by `getLoginInfo` (`zpw_service_map_v3`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceDirectory {
    pub chat: Vec<String>,
    pub group: Vec<String>,
    pub group_poll: Vec<String>,
    pub group_board: Vec<String>,
    pub file: Vec<String>,
    pub friend: Vec<String>,
    pub friend_board: Vec<String>,
    pub profile: Vec<String>,
    pub reaction: Vec<String>,
    pub sticker: Vec<String>,
    pub alias: Vec<String>,
    pub conversation: Vec<String>,
    pub auto_reply: Vec<String>,
    pub quick_message: Vec<String>,
    pub catalog: Vec<String>,
    pub label: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl ServiceDirectory {
    /// Resolves the primary base URL for a named Zalo microservice cluster.
    pub fn endpoint_or<'a>(&'a self, list: &'a [String], fallback: &'a str) -> &'a str {
        list.first().map(String::as_str).unwrap_or(fallback)
    }

    pub fn chat_base(&self) -> &str {
        self.endpoint_or(&self.chat, "https://tt-chat1-wpa.chat.zalo.me")
    }

    pub fn group_base(&self) -> &str {
        self.endpoint_or(&self.group, "https://tt-group-wpa.chat.zalo.me")
    }

    pub fn group_poll_base(&self) -> &str {
        self.endpoint_or(&self.group_poll, self.group_base())
    }

    pub fn file_base(&self) -> &str {
        self.endpoint_or(&self.file, "https://tt-files-wpa.chat.zalo.me")
    }

    pub fn friend_base(&self) -> &str {
        self.endpoint_or(&self.friend, "https://tt-friend-wpa.chat.zalo.me")
    }

    pub fn profile_base(&self) -> &str {
        self.endpoint_or(&self.profile, "https://tt-profile-wpa.chat.zalo.me")
    }

    pub fn reaction_base(&self) -> &str {
        self.endpoint_or(&self.reaction, "https://reaction.chat.zalo.me")
    }

    pub fn sticker_base(&self) -> &str {
        self.endpoint_or(&self.sticker, "https://sticker.zadn.vn")
    }
}

/// Server-provided upload & socket tuning parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeSettings {
    pub features: FeatureLimits,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FeatureLimits {
    pub sharefile: ShareFileLimits,
    pub socket: SocketLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ShareFileLimits {
    pub chunk_size_file: usize,
    pub max_file: usize,
    pub max_size_share_file_v3: usize,
    pub restricted_ext_file: Vec<String>,
}

impl Default for ShareFileLimits {
    fn default() -> Self {
        Self {
            chunk_size_file: 2 * 1024 * 1024, // 2 MiB default chunk
            max_file: 50,
            max_size_share_file_v3: 100, // 100 MiB
            restricted_ext_file: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SocketLimits {
    pub ping_interval: u64,
    pub close_and_retry_codes: Vec<u16>,
    pub rotate_error_codes: Vec<u16>,
}

impl Default for SocketLimits {
    fn default() -> Self {
        Self {
            ping_interval: 180_000, // 3 minutes
            close_and_retry_codes: vec![1006, 3003],
            rotate_error_codes: vec![1006],
        }
    }
}

/// Sync version counters returned in `getServerInfo` (`extra_ver`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtraVersions {
    pub phonebook: u64,
    pub friend: Value,
    pub alias: Value,
    pub conv_label: Value,
}

/// Top-level `getServerInfo` payload (handles Zalo's historic `setttings` typo seamlessly).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerInfoEnvelope {
    #[serde(alias = "setttings")]
    pub settings: RuntimeSettings,
    pub extra_ver: ExtraVersions,
}

/// Top-level decrypted `getLoginInfo` payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginBootstrapData {
    pub uid: String,
    pub zpw_enk: String,
    pub zpw_ws: Vec<String>,
    pub zpw_service_map_v3: ServiceDirectory,
    pub send2me_id: String,
    pub language: String,
}

/// Notification dispatched over WebSocket (`cmd = 601`, `act_type = "file_done"`)
/// when an async video/document upload completes server-side processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadedMediaNotice {
    pub file_id: String,
    pub file_url: String,
}
