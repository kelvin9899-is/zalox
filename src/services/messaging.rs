//! Fluent message composition, rich-text formatting, reactions, stickers,
//! recalls, deletions, forwards, and typing indicators.

use std::ops::Range;

use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    error::{ZaloxError, ZaloxResult},
    realtime::IncomingMessage,
    session::{now_epoch_ms, ZaloxSession},
    types::{ChannelKind, Peer},
};

/// Visual text decoration codes supported in Zalo rich-text messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextDecoration {
    Bold,
    Italic,
    Underline,
    Strikethrough,
    Red,
    Orange,
    Yellow,
    Green,
    SmallFont,
    LargeFont,
    BulletList,
    NumberedList,
    Indent(u8),
}

impl TextDecoration {
    fn wire_code(&self) -> String {
        match self {
            Self::Bold => "b".into(),
            Self::Italic => "i".into(),
            Self::Underline => "u".into(),
            Self::Strikethrough => "s".into(),
            Self::Red => "c_db342e".into(),
            Self::Orange => "c_f27806".into(),
            Self::Yellow => "c_f7b503".into(),
            Self::Green => "c_15a85f".into(),
            Self::SmallFont => "f_13".into(),
            Self::LargeFont => "f_18".into(),
            Self::BulletList => "lst_1".into(),
            Self::NumberedList => "lst_2".into(),
            Self::Indent(spaces) => format!("ind_{}0", (*spaces).max(1)),
        }
    }
}

/// Character range styling span inside a message body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanStyle {
    pub start: usize,
    pub len: usize,
    pub decoration: TextDecoration,
}

/// Priority badge displayed on a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageUrgency {
    Normal = 0,
    Important = 1,
    Urgent = 2,
}

/// Group `@mention` span (`uid = "-1"` represents `@All`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MentionSpan {
    pub uid: String,
    pub pos: usize,
    pub len: usize,
}

#[derive(Debug, Clone)]
struct QuoteTarget {
    owner_uid: String,
    msg_id: String,
    cli_msg_id: String,
    msg_type_code: i64,
    ts_str: String,
    text_preview: String,
    ttl: u64,
}

/// Built-in reaction icons with their exact `(icon_str, r_type, source)` wire identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactionKind {
    Heart,
    Like,
    Haha,
    Wow,
    Cry,
    Angry,
    Dislike,
    Kiss,
    TearsOfJoy,
    Rose,
    BrokenHeart,
    Love,
    Ok,
    Peace,
    Thanks,
    Pray,
    Clap,
    Beer,
    Clear,
    Custom {
        icon: String,
        r_type: i32,
        source: i32,
    },
}

impl ReactionKind {
    fn wire_tuple(&self) -> (&str, i32, i32) {
        match self {
            Self::Heart => ("/-heart", 5, 6),
            Self::Like => ("/-strong", 3, 6),
            Self::Haha => (":>", 0, 6),
            Self::Wow => (":o", 32, 6),
            Self::Cry => (":((", 2, 6),
            Self::Angry => (":-h", 20, 6),
            Self::Dislike => ("/-weak", 4, 6),
            Self::Kiss => (":-*", 8, 6),
            Self::TearsOfJoy => (":')", 7, 6),
            Self::Rose => ("/-rose", 120, 6),
            Self::BrokenHeart => ("/-break", 65, 6),
            Self::Love => (":x", 29, 6),
            Self::Ok => ("/-ok", 68, 6),
            Self::Peace => ("/-v", 69, 6),
            Self::Thanks => ("/-thanks", 70, 6),
            Self::Pray => ("/-pray", 73, 6),
            Self::Clap => ("=D>", 46, 6),
            Self::Beer => ("/-beer", 99, 6),
            Self::Clear => ("", -1, 6),
            Self::Custom {
                icon,
                r_type,
                source,
            } => (icon.as_str(), *r_type, *source),
        }
    }
}

/// Delivery receipt returned when sending a message or sticker.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessageReceipt {
    #[serde(rename = "msgId", deserialize_with = "de_str_or_num")]
    pub msg_id: String,
}

fn de_str_or_num<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;
    Ok(match v {
        Value::String(s) => s,
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    })
}

/// Fluent builder for constructing and dispatching rich Zalo text messages.
pub struct MessageDraft {
    session: ZaloxSession,
    peer: Peer,
    body: String,
    styles: Vec<SpanStyle>,
    mentions: Vec<MentionSpan>,
    urgency: MessageUrgency,
    quote: Option<QuoteTarget>,
    ttl_ms: u64,
}

impl MessageDraft {
    pub fn text(mut self, content: impl Into<String>) -> Self {
        self.body = content.into();
        self
    }

    pub fn style(mut self, range: Range<usize>, decoration: TextDecoration) -> Self {
        if range.end > range.start {
            self.styles.push(SpanStyle {
                start: range.start,
                len: range.end - range.start,
                decoration,
            });
        }
        self
    }

    pub fn bold(self, range: Range<usize>) -> Self {
        self.style(range, TextDecoration::Bold)
    }

    pub fn italic(self, range: Range<usize>) -> Self {
        self.style(range, TextDecoration::Italic)
    }

    pub fn underline(self, range: Range<usize>) -> Self {
        self.style(range, TextDecoration::Underline)
    }

    pub fn urgency(mut self, level: MessageUrgency) -> Self {
        self.urgency = level;
        self
    }

    pub fn mention(mut self, uid: impl Into<String>, pos: usize, len: usize) -> Self {
        self.mentions.push(MentionSpan {
            uid: uid.into(),
            pos,
            len,
        });
        self
    }

    pub fn mention_all(self, pos: usize, len: usize) -> Self {
        self.mention("-1", pos, len)
    }

    pub fn quote_message(mut self, incoming: &IncomingMessage) -> Self {
        self.quote = Some(QuoteTarget {
            owner_uid: incoming.sender_id.clone(),
            msg_id: incoming.msg_id.clone(),
            cli_msg_id: incoming.cli_msg_id.clone(),
            msg_type_code: map_client_msg_type(&incoming.msg_type),
            ts_str: incoming.timestamp_ms.to_string(),
            text_preview: incoming.text().unwrap_or_default().to_owned(),
            ttl: incoming.ttl,
        });
        self
    }

    pub fn ttl_ms(mut self, ttl_ms: u64) -> Self {
        self.ttl_ms = ttl_ms;
        self
    }

    /// Encrypts and dispatches the composed message to Zalo.
    pub async fn send(self) -> ZaloxResult<MessageReceipt> {
        if self.body.is_empty() {
            return Err(ZaloxError::InvalidInput(
                "Message text cannot be empty".into(),
            ));
        }

        let is_group = self.peer.is_group();
        let client_id = now_epoch_ms();
        let mut params = Map::new();
        params.insert("message".into(), Value::String(self.body.clone()));
        params.insert("clientId".into(), json!(client_id));
        params.insert("ttl".into(), json!(self.ttl_ms));

        if is_group {
            params.insert("grid".into(), Value::String(self.peer.id.clone()));
            params.insert("visibility".into(), json!(0));
        } else {
            params.insert("toid".into(), Value::String(self.peer.id.clone()));
            params.insert("imei".into(), Value::String(self.session.core.imei.clone()));
        }

        let has_mentions = is_group && !self.mentions.is_empty();
        if has_mentions {
            let mention_items: Vec<Value> = self
                .mentions
                .iter()
                .map(|m| {
                    json!({
                        "pos": m.pos,
                        "uid": m.uid,
                        "len": m.len,
                        "type": if m.uid == "-1" { 1 } else { 0 },
                    })
                })
                .collect();
            params.insert(
                "mentionInfo".into(),
                Value::String(serde_json::to_string(&mention_items)?),
            );
        }

        if !self.styles.is_empty() {
            let style_list: Vec<Value> = self
                .styles
                .iter()
                .map(|s| {
                    json!({
                        "start": s.start,
                        "len": s.len,
                        "st": s.decoration.wire_code(),
                    })
                })
                .collect();
            let text_props = json!({
                "styles": style_list,
                "ver": 0,
            });
            params.insert(
                "textProperties".into(),
                Value::String(serde_json::to_string(&text_props)?),
            );
        }

        if self.urgency != MessageUrgency::Normal {
            params.insert("metaData".into(), json!({ "urgency": self.urgency as u8 }));
        }

        let action_suffix = if let Some(q) = &self.quote {
            params.insert("qmsgOwner".into(), Value::String(q.owner_uid.clone()));
            params.insert("qmsgId".into(), Value::String(q.msg_id.clone()));
            params.insert("qmsgCliId".into(), Value::String(q.cli_msg_id.clone()));
            params.insert("qmsgType".into(), json!(q.msg_type_code));
            params.insert("qmsgTs".into(), Value::String(q.ts_str.clone()));
            params.insert("qmsg".into(), Value::String(q.text_preview.clone()));
            params.insert("qmsgTTL".into(), json!(q.ttl));
            if is_group {
                params.insert(
                    "qmsgAttach".into(),
                    Value::String(
                        r#"{"properties":{"color":0,"size":0,"type":0,"subType":0,"ext":"{\"shouldParseLinkOrContact\":0}"}}"#.into(),
                    ),
                );
            }
            "quote"
        } else if is_group {
            if has_mentions {
                "mention"
            } else {
                "sendmsg"
            }
        } else {
            "sms"
        };

        let base_path = if is_group {
            format!(
                "{}/api/group/{action_suffix}",
                self.session.core.services.group_base()
            )
        } else {
            format!(
                "{}/api/message/{action_suffix}",
                self.session.core.services.chat_base()
            )
        };

        let url = self.session.core.gateway.build_endpoint_url(
            &base_path,
            &[("nretry", "0".into())],
            true,
        )?;

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &Value::Object(params), true)
            .await
    }
}

/// Domain facade for all messaging, reaction, sticker, and conversation state actions.
#[derive(Clone)]
pub struct MessagingService {
    session: ZaloxSession,
}

impl MessagingService {
    pub(crate) fn new(session: ZaloxSession) -> Self {
        Self { session }
    }

    /// Starts building a rich message targeting `peer`.
    pub fn compose(&self, peer: Peer) -> MessageDraft {
        MessageDraft {
            session: self.session.clone(),
            peer,
            body: String::new(),
            styles: Vec::new(),
            mentions: Vec::new(),
            urgency: MessageUrgency::Normal,
            quote: None,
            ttl_ms: 0,
        }
    }

    /// Shortcut to send a plain UTF-8 text message to `peer`.
    pub async fn send_text(
        &self,
        peer: Peer,
        text: impl Into<String>,
    ) -> ZaloxResult<MessageReceipt> {
        self.compose(peer).text(text).send().await
    }

    /// Shortcut to quote-reply directly to an `IncomingMessage`.
    pub async fn quote_reply(
        &self,
        incoming: &IncomingMessage,
        text: impl Into<String>,
    ) -> ZaloxResult<MessageReceipt> {
        self.compose(incoming.peer.clone())
            .text(text)
            .quote_message(incoming)
            .send()
            .await
    }

    /// Recalls ("undo") a previously sent message for everyone in the conversation.
    pub async fn recall(&self, peer: Peer, msg_id: &str, cli_msg_id: &str) -> ZaloxResult<Value> {
        let mut params = Map::new();
        params.insert("msgId".into(), Value::String(msg_id.to_owned()));
        params.insert("clientId".into(), json!(now_epoch_ms()));
        params.insert("cliMsgIdUndo".into(), Value::String(cli_msg_id.to_owned()));

        let base = if peer.is_group() {
            params.insert("grid".into(), Value::String(peer.id));
            params.insert("visibility".into(), json!(0));
            params.insert("imei".into(), Value::String(self.session.core.imei.clone()));
            format!(
                "{}/api/group/undomsg",
                self.session.core.services.group_base()
            )
        } else {
            params.insert("toid".into(), Value::String(peer.id));
            format!(
                "{}/api/message/undo",
                self.session.core.services.chat_base()
            )
        };

        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &Value::Object(params), true)
            .await
    }

    /// Deletes a message locally (`only_me = true`) or in a group (`only_me = false` if permitted).
    pub async fn delete_message(
        &self,
        peer: Peer,
        msg_id: &str,
        cli_msg_id: &str,
        owner_uid: &str,
        only_me: bool,
    ) -> ZaloxResult<Value> {
        if !peer.is_group() && !only_me {
            return Err(ZaloxError::InvalidInput(
                "Deleting for everyone in a 1-on-1 chat requires `recall` instead of `delete_message`".into(),
            ));
        }

        let is_group = peer.is_group();
        let mut params = Map::new();
        params.insert(
            if is_group { "grid" } else { "toid" }.into(),
            Value::String(peer.id.clone()),
        );
        params.insert("cliMsgId".into(), json!(now_epoch_ms()));
        params.insert(
            "msgs".into(),
            json!([{
                "cliMsgId": cli_msg_id,
                "globalMsgId": msg_id,
                "ownerId": owner_uid,
                "destId": peer.id,
            }]),
        );
        params.insert("onlyMe".into(), json!(u8::from(only_me)));
        if !is_group {
            params.insert("imei".into(), Value::String(self.session.core.imei.clone()));
        }

        let base = if is_group {
            format!(
                "{}/api/group/deletemsg",
                self.session.core.services.group_base()
            )
        } else {
            format!(
                "{}/api/message/delete",
                self.session.core.services.chat_base()
            )
        };

        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &Value::Object(params), true)
            .await
    }

    /// Forwards a text message to multiple users or groups simultaneously.
    pub async fn forward_text(
        &self,
        text: &str,
        target_ids: &[String],
        kind: ChannelKind,
        ttl_ms: u64,
    ) -> ZaloxResult<Value> {
        if text.is_empty() || target_ids.is_empty() {
            return Err(ZaloxError::InvalidInput(
                "Forward text and target_ids must be non-empty".into(),
            ));
        }

        let client_id = now_epoch_ms().to_string();
        let msg_info = serde_json::to_string(&json!({ "message": text }))?;

        let (base, params) = match kind {
            ChannelKind::Direct => {
                let to_ids: Vec<Value> = target_ids
                    .iter()
                    .map(|id| json!({ "clientId": client_id, "toUid": id, "ttl": ttl_ms }))
                    .collect();
                (
                    format!(
                        "{}/api/message/mforward",
                        self.session.core.services.file_base()
                    ),
                    json!({
                        "toIds": to_ids,
                        "imei": self.session.core.imei,
                        "ttl": ttl_ms,
                        "msgType": "1",
                        "totalIds": target_ids.len(),
                        "msgInfo": msg_info,
                        "decorLog": "null",
                    }),
                )
            }
            ChannelKind::Group => {
                let grids: Vec<Value> = target_ids
                    .iter()
                    .map(|id| json!({ "clientId": client_id, "grid": id, "ttl": ttl_ms }))
                    .collect();
                (
                    format!(
                        "{}/api/group/mforward",
                        self.session.core.services.file_base()
                    ),
                    json!({
                        "grids": grids,
                        "ttl": ttl_ms,
                        "msgType": "1",
                        "totalIds": target_ids.len(),
                        "msgInfo": msg_info,
                        "decorLog": "null",
                    }),
                )
            }
        };

        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, true)
            .await
    }

    /// Adds or clears a reaction on a specific message.
    pub async fn react(
        &self,
        peer: Peer,
        msg_id: &str,
        cli_msg_id: &str,
        reaction: ReactionKind,
    ) -> ZaloxResult<Value> {
        let g_id: i64 = msg_id.parse().map_err(|_| {
            ZaloxError::InvalidInput(format!("Numeric msgId required, got '{msg_id}'"))
        })?;
        let c_id: i64 = cli_msg_id.parse().map_err(|_| {
            ZaloxError::InvalidInput(format!("Numeric cliMsgId required, got '{cli_msg_id}'"))
        })?;

        let (r_icon, r_type, source) = reaction.wire_tuple();
        let inner_msg = serde_json::to_string(&json!({
            "rMsg": [{
                "gMsgID": g_id,
                "cMsgID": c_id,
                "msgType": 1,
            }],
            "rIcon": r_icon,
            "rType": r_type,
            "source": source,
        }))?;

        let mut params = Map::new();
        params.insert(
            "react_list".into(),
            json!([{
                "message": inner_msg,
                "clientId": now_epoch_ms(),
            }]),
        );

        let base = if peer.is_group() {
            params.insert("grid".into(), Value::String(peer.id));
            params.insert("imei".into(), Value::String(self.session.core.imei.clone()));
            format!(
                "{}/api/group/reaction",
                self.session.core.services.reaction_base()
            )
        } else {
            params.insert("toid".into(), Value::String(peer.id));
            format!(
                "{}/api/message/reaction",
                self.session.core.services.reaction_base()
            )
        };

        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &Value::Object(params), true)
            .await
    }

    /// Sends a Zalo sticker by `(sticker_id, category_id, sticker_type)`.
    pub async fn send_sticker(
        &self,
        peer: Peer,
        sticker_id: u64,
        category_id: u64,
        sticker_type: u32,
    ) -> ZaloxResult<MessageReceipt> {
        let mut params = Map::new();
        params.insert("stickerId".into(), json!(sticker_id));
        params.insert("cateId".into(), json!(category_id));
        params.insert("type".into(), json!(sticker_type));
        params.insert("clientId".into(), json!(now_epoch_ms()));
        params.insert("imei".into(), Value::String(self.session.core.imei.clone()));
        params.insert("zsource".into(), json!(101));

        let base = if peer.is_group() {
            params.insert("grid".into(), Value::String(peer.id));
            format!(
                "{}/api/group/sticker",
                self.session.core.services.group_base()
            )
        } else {
            params.insert("toid".into(), Value::String(peer.id));
            format!(
                "{}/api/message/sticker",
                self.session.core.services.chat_base()
            )
        };

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

    /// Broadcasts a typing indicator ("đang soạn tin...") to `peer`.
    pub async fn send_typing(&self, peer: Peer) -> ZaloxResult<Value> {
        let (base, params) = if peer.is_group() {
            (
                format!(
                    "{}/api/group/typing",
                    self.session.core.services.group_base()
                ),
                json!({
                    "grid": peer.id,
                    "imei": self.session.core.imei,
                }),
            )
        } else {
            (
                format!(
                    "{}/api/message/typing",
                    self.session.core.services.chat_base()
                ),
                json!({
                    "toid": peer.id,
                    "destType": 3,
                    "imei": self.session.core.imei,
                }),
            )
        };

        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, false)
            .await
    }

    /// Pings the HTTP keep-alive endpoint to refresh active web presence.
    pub async fn keep_alive(&self) -> ZaloxResult<Value> {
        let base = format!("{}/keepalive", self.session.core.services.chat_base());
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({ "imei": self.session.core.imei });
        self.session
            .core
            .gateway
            .request_encrypted_query(
                Method::GET,
                url,
                &self.session.core.cipher,
                &params,
                false,
                false,
            )
            .await
    }
}

fn map_client_msg_type(msg_type: &str) -> i64 {
    match msg_type {
        "chat.voice" => 31,
        "chat.photo" => 32,
        "chat.sticker" => 36,
        "chat.doodle" => 37,
        "chat.recommended" | "chat.link" => 38,
        "chat.location.new" => 43,
        "chat.video.msg" => 44,
        "share.file" => 46,
        "chat.gif" => 49,
        _ => 1,
    }
}
