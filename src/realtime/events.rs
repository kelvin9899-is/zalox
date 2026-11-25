//! Typed real-time push event models decoded from Zalo's WebSocket stream.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::{ChannelKind, Peer, UploadedMediaNotice};

/// Top-level event broadcast to subscribers on a live `RealtimeHandle`.
#[derive(Debug, Clone)]
pub enum RealtimeEvent {
    /// WebSocket connected and negotiated its per-connection AES-GCM cipher key.
    Connected { endpoint: String },
    /// WebSocket disconnected (will auto-reconnect if configured).
    Disconnected { code: u16, reason: String },
    /// Another Zalo Web tab/client opened and displaced this listener (`cmd = 3000`).
    SessionDisplaced,
    /// A new direct or group message arrived.
    MessageReceived(Box<IncomingMessage>),
    /// A message was recalled ("undo") by its sender.
    MessageRecalled(Box<RecallNotice>),
    /// A reaction was added or updated on a message.
    ReactionChanged(Box<ReactionNotice>),
    /// A user started typing in a direct or group conversation.
    TypingChanged(TypingNotice),
    /// Group membership, title, link, or board state changed.
    GroupActivity(GroupNotice),
    /// Friend request, acceptance, or block event occurred.
    FriendActivity(FriendNotice),
    /// Asynchronous file/video upload finished processing on Zalo's servers.
    UploadReady(UploadedMediaNotice),
}

/// Content variant inside an `IncomingMessage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageBody {
    Text(String),
    Structured(Value),
}

impl MessageBody {
    /// Returns the plain text slice if this message is a standard text message.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t.as_str()),
            Self::Structured(_) => None,
        }
    }
}

/// Quoted message reference attached to an `IncomingMessage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteMetadata {
    pub owner_id: String,
    pub cli_msg_id: String,
    pub global_msg_id: String,
    pub msg_type: i64,
    pub timestamp_ms: u64,
    pub text: String,
    pub ttl: u64,
}

/// Normalized incoming message across both Direct (`cmd = 501`) and Group (`cmd = 521`) channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingMessage {
    pub peer: Peer,
    pub msg_id: String,
    pub cli_msg_id: String,
    pub msg_type: String,
    pub sender_id: String,
    pub sender_name: String,
    pub recipient_id: String,
    pub timestamp_ms: u64,
    pub ttl: u64,
    pub is_self: bool,
    pub body: MessageBody,
    pub quote: Option<QuoteMetadata>,
    pub raw: Value,
}

impl IncomingMessage {
    /// Parses a raw message JSON object from `msgs` or `groupMsgs`.
    pub(crate) fn from_wire(own_uid: &str, kind: ChannelKind, raw: Value) -> Self {
        let raw_from = value_to_string(raw.get("uidFrom"));
        let raw_to = value_to_string(raw.get("idTo"));
        let is_self = raw_from == "0" || raw_from == own_uid;

        let sender_id = if raw_from == "0" {
            own_uid.to_owned()
        } else {
            raw_from
        };
        let recipient_id = if raw_to == "0" {
            own_uid.to_owned()
        } else {
            raw_to.clone()
        };

        let peer_id = match kind {
            ChannelKind::Direct => {
                if is_self {
                    recipient_id.clone()
                } else {
                    sender_id.clone()
                }
            }
            ChannelKind::Group => raw_to,
        };

        let body = match raw.get("content") {
            Some(Value::String(s)) => MessageBody::Text(s.clone()),
            Some(other) => MessageBody::Structured(other.clone()),
            None => MessageBody::Text(String::new()),
        };

        let quote = raw.get("quote").and_then(parse_quote_metadata);

        Self {
            peer: Peer { id: peer_id, kind },
            msg_id: value_to_string(raw.get("msgId")),
            cli_msg_id: value_to_string(raw.get("cliMsgId")),
            msg_type: value_to_string(raw.get("msgType")),
            sender_id,
            sender_name: value_to_string(raw.get("dName")),
            recipient_id,
            timestamp_ms: value_to_u64(raw.get("ts")),
            ttl: value_to_u64(raw.get("ttl")),
            is_self,
            body,
            quote,
            raw,
        }
    }

    /// Convenience accessor for plain-text content.
    pub fn text(&self) -> Option<&str> {
        self.body.as_text()
    }
}

/// Recall ("undo") event notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallNotice {
    pub peer: Peer,
    pub sender_id: String,
    pub global_msg_id: String,
    pub cli_msg_id: String,
    pub is_self: bool,
    pub raw: Value,
}

impl RecallNotice {
    pub(crate) fn from_wire(own_uid: &str, kind: ChannelKind, raw: Value) -> Self {
        let raw_from = value_to_string(raw.get("uidFrom"));
        let raw_to = value_to_string(raw.get("idTo"));
        let is_self = raw_from == "0" || raw_from == own_uid;
        let sender_id = if raw_from == "0" {
            own_uid.to_owned()
        } else {
            raw_from
        };
        let peer_id = match kind {
            ChannelKind::Direct => {
                if is_self {
                    if raw_to == "0" {
                        own_uid.to_owned()
                    } else {
                        raw_to
                    }
                } else {
                    sender_id.clone()
                }
            }
            ChannelKind::Group => raw_to,
        };

        let del = raw.get("content").and_then(|c| c.get("deleteMsg"));
        Self {
            peer: Peer { id: peer_id, kind },
            sender_id,
            global_msg_id: value_to_string(
                del.and_then(|d| d.get("globalMsgId"))
                    .or_else(|| raw.get("msgId")),
            ),
            cli_msg_id: value_to_string(
                del.and_then(|d| d.get("cliMsgId"))
                    .or_else(|| raw.get("cliMsgId")),
            ),
            is_self,
            raw,
        }
    }
}

/// Reaction update notification (`cmd = 612`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionNotice {
    pub peer: Peer,
    pub sender_id: String,
    pub msg_id: String,
    pub icon: String,
    pub is_self: bool,
    pub raw: Value,
}

/// Typing indicator notification (`cmd = 602`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingNotice {
    pub peer: Peer,
    pub user_id: String,
}

/// Group control event (`cmd = 601`, `act_type = "group"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupNotice {
    pub action: String,
    pub group_id: String,
    pub data: Value,
}

/// Friend control event (`cmd = 601`, `act_type = "fr"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendNotice {
    pub action: String,
    pub data: Value,
}

fn parse_quote_metadata(q: &Value) -> Option<QuoteMetadata> {
    if !q.is_object() {
        return None;
    }
    Some(QuoteMetadata {
        owner_id: value_to_string(q.get("ownerId")),
        cli_msg_id: value_to_string(q.get("cliMsgId")),
        global_msg_id: value_to_string(q.get("globalMsgId")),
        msg_type: q.get("cliMsgType").and_then(Value::as_i64).unwrap_or(1),
        timestamp_ms: value_to_u64(q.get("ts")),
        text: value_to_string(q.get("msg")),
        ttl: value_to_u64(q.get("ttl")),
    })
}

pub(crate) fn value_to_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

pub(crate) fn value_to_u64(v: Option<&Value>) -> u64 {
    match v {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}
