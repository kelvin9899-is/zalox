//! WebSocket connection supervisor, automatic endpoint rotation, heartbeat,
//! and broadcast channel fan-out.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::{
    sync::{broadcast, watch},
    time::interval,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message as WsMessage},
};

use crate::{
    cipher::{unpack_push_envelope, WireFrame},
    error::{ZaloxError, ZaloxResult},
    realtime::events::{
        value_to_string, FriendNotice, GroupNotice, IncomingMessage, ReactionNotice, RealtimeEvent,
        RecallNotice, TypingNotice,
    },
    session::{now_epoch_ms, ZaloxSession},
    types::{ChannelKind, Peer, UploadedMediaNotice},
};

/// Reconnection and buffering options for `RealtimeHandle`.
#[derive(Debug, Clone)]
pub struct EventStreamConfig {
    /// Automatically reconnect with backoff if the socket drops unexpectedly.
    pub auto_reconnect: bool,
    /// Initial delay before reconnecting after an abnormal drop.
    pub initial_backoff: Duration,
    /// Maximum delay cap for exponential backoff.
    pub max_backoff: Duration,
    /// Broadcast ring-buffer capacity for subscribers.
    pub channel_capacity: usize,
}

impl Default for EventStreamConfig {
    fn default() -> Self {
        Self {
            auto_reconnect: true,
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(30),
            channel_capacity: 512,
        }
    }
}

/// Active handle to a background WebSocket supervisor task.
pub struct RealtimeHandle {
    events_tx: broadcast::Sender<RealtimeEvent>,
    shutdown_tx: watch::Sender<bool>,
}

impl RealtimeHandle {
    pub(crate) fn connect(session: ZaloxSession, cfg: EventStreamConfig) -> ZaloxResult<Self> {
        if session.core.ws_endpoints.is_empty() {
            return Err(ZaloxError::Realtime(
                "Session contains no zpw_ws WebSocket endpoints".into(),
            ));
        }

        let (events_tx, _) = broadcast::channel(cfg.channel_capacity);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let tx_clone = events_tx.clone();
        tokio::spawn(async move {
            run_supervisor_loop(session, cfg, tx_clone, shutdown_rx).await;
        });

        Ok(Self {
            events_tx,
            shutdown_tx,
        })
    }

    /// Creates a new broadcast receiver to consume `RealtimeEvent`s.
    pub fn receiver(&self) -> broadcast::Receiver<RealtimeEvent> {
        self.events_tx.subscribe()
    }

    /// Gracefully terminates the background WebSocket listener task.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

async fn run_supervisor_loop(
    session: ZaloxSession,
    cfg: EventStreamConfig,
    events_tx: broadcast::Sender<RealtimeEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let endpoints = session.core.ws_endpoints.clone();
    let mut endpoint_idx = 0usize;
    let mut backoff = cfg.initial_backoff;

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        let raw_endpoint = &endpoints[endpoint_idx % endpoints.len()];
        let outcome = run_single_socket(&session, raw_endpoint, &events_tx, &mut shutdown_rx).await;

        if *shutdown_rx.borrow() {
            break;
        }

        match outcome {
            SocketExit::Displaced | SocketExit::CleanShutdown => break,
            SocketExit::Dropped { code, reason } => {
                let _ = events_tx.send(RealtimeEvent::Disconnected {
                    code,
                    reason: reason.clone(),
                });

                if !cfg.auto_reconnect {
                    break;
                }

                endpoint_idx = (endpoint_idx + 1) % endpoints.len();
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
                backoff = (backoff * 2).min(cfg.max_backoff);
            }
            SocketExit::ConnectedThenDropped { code, reason } => {
                backoff = cfg.initial_backoff;
                let _ = events_tx.send(RealtimeEvent::Disconnected { code, reason });
                if !cfg.auto_reconnect {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

enum SocketExit {
    CleanShutdown,
    Displaced,
    Dropped { code: u16, reason: String },
    ConnectedThenDropped { code: u16, reason: String },
}

async fn run_single_socket(
    session: &ZaloxSession,
    base_ws_url: &str,
    events_tx: &broadcast::Sender<RealtimeEvent>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> SocketExit {
    let ws_url = match session.core.gateway.build_endpoint_url(
        base_ws_url,
        &[("t", now_epoch_ms().to_string())],
        true,
    ) {
        Ok(u) => u,
        Err(e) => {
            return SocketExit::Dropped {
                code: 1006,
                reason: e.to_string(),
            }
        }
    };

    let cookie_header = match session.core.gateway.cookie_header_for_ws() {
        Ok(c) => c,
        Err(e) => {
            return SocketExit::Dropped {
                code: 1006,
                reason: e.to_string(),
            }
        }
    };

    let mut req = match ws_url.as_str().into_client_request() {
        Ok(r) => r,
        Err(e) => {
            return SocketExit::Dropped {
                code: 1006,
                reason: e.to_string(),
            }
        }
    };

    {
        let headers = req.headers_mut();
        if let Ok(v) = "https://chat.zalo.me".parse() {
            headers.insert("Origin", v);
        }
        if let Ok(v) = session.core.gateway.user_agent().parse() {
            headers.insert("User-Agent", v);
        }
        if !cookie_header.is_empty() {
            if let Ok(v) = cookie_header.parse() {
                headers.insert("Cookie", v);
            }
        }
    }

    let (ws_stream, _) = match connect_async(req).await {
        Ok(pair) => pair,
        Err(e) => {
            return SocketExit::Dropped {
                code: 1006,
                reason: e.to_string(),
            }
        }
    };

    let (mut sink, mut stream) = ws_stream.split();
    let ping_ms = session
        .core
        .settings
        .features
        .socket
        .ping_interval
        .max(30_000);
    let mut ping_ticker = interval(Duration::from_millis(ping_ms));
    ping_ticker.tick().await; // consume immediate first tick

    let mut ws_cipher_key: Option<String> = None;
    let mut established = false;

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    let _ = sink.close().await;
                    return SocketExit::CleanShutdown;
                }
            }
            _ = ping_ticker.tick(), if ws_cipher_key.is_some() => {
                if let Ok(bytes) = WireFrame::heartbeat(now_epoch_ms()).encode_bytes() {
                    if sink.send(WsMessage::Binary(bytes.to_vec())).await.is_err() {
                        return SocketExit::ConnectedThenDropped {
                            code: 1006,
                            reason: "Failed to send heartbeat frame".into(),
                        };
                    }
                }
            }
            maybe_msg = stream.next() => {
                let Some(frame_res) = maybe_msg else {
                    return if established {
                        SocketExit::ConnectedThenDropped { code: 1006, reason: "EOF".into() }
                    } else {
                        SocketExit::Dropped { code: 1006, reason: "EOF before handshake".into() }
                    };
                };

                match frame_res {
                    Ok(WsMessage::Binary(bin)) => {
                        if let Ok((hdr, Some(json_env))) = WireFrame::decode_bytes(&bin) {
                            if hdr.version == 1 && hdr.command == 3000 && hdr.sub_command == 0 {
                                let _ = events_tx.send(RealtimeEvent::SessionDisplaced);
                                let _ = sink.close().await;
                                return SocketExit::Displaced;
                            }

                            if hdr.version == 1 && hdr.command == 1 && hdr.sub_command == 1 {
                                if let Some(key) = json_env.get("key").and_then(Value::as_str) {
                                    ws_cipher_key = Some(key.to_owned());
                                    established = true;
                                    let _ = events_tx.send(RealtimeEvent::Connected {
                                        endpoint: base_ws_url.to_owned(),
                                    });
                                }
                                continue;
                            }

                            dispatch_inbound_frame(
                                session,
                                hdr.version,
                                hdr.command,
                                hdr.sub_command,
                                &json_env,
                                ws_cipher_key.as_deref(),
                                events_tx,
                            )
                            .await;
                        }
                    }
                    Ok(WsMessage::Close(close_opt)) => {
                        let (code, reason) = close_opt
                            .map(|c| (u16::from(c.code), c.reason.to_string()))
                            .unwrap_or((1000, String::new()));
                        if code == 3000 {
                            let _ = events_tx.send(RealtimeEvent::SessionDisplaced);
                            return SocketExit::Displaced;
                        }
                        return if established {
                            SocketExit::ConnectedThenDropped { code, reason }
                        } else {
                            SocketExit::Dropped { code, reason }
                        };
                    }
                    Ok(_) => {}
                    Err(e) => {
                        return if established {
                            SocketExit::ConnectedThenDropped { code: 1006, reason: e.to_string() }
                        } else {
                            SocketExit::Dropped { code: 1006, reason: e.to_string() }
                        };
                    }
                }
            }
        }
    }
}

async fn dispatch_inbound_frame(
    session: &ZaloxSession,
    version: u8,
    cmd: u16,
    sub_cmd: u8,
    envelope: &Value,
    cipher_key: Option<&str>,
    events_tx: &broadcast::Sender<RealtimeEvent>,
) {
    let own_uid = session.uid();
    let allow_self = session.core.self_events;

    // Direct messages & recalls (`cmd = 501` or `551`, `sub_cmd = 0`)
    if version == 1 && (cmd == 501 || cmd == 551) && sub_cmd == 0 {
        if let Ok(decoded) = unpack_push_envelope(envelope, cipher_key) {
            if let Some(msgs) = decoded
                .get("data")
                .and_then(|d| d.get("msgs"))
                .and_then(Value::as_array)
            {
                for m in msgs {
                    if is_recall_entry(m) {
                        let notice =
                            RecallNotice::from_wire(own_uid, ChannelKind::Direct, m.clone());
                        if !notice.is_self || allow_self {
                            let _ =
                                events_tx.send(RealtimeEvent::MessageRecalled(Box::new(notice)));
                        }
                    } else {
                        let msg =
                            IncomingMessage::from_wire(own_uid, ChannelKind::Direct, m.clone());
                        if !msg.is_self || allow_self {
                            let _ = events_tx.send(RealtimeEvent::MessageReceived(Box::new(msg)));
                        }
                    }
                }
            }
        }
        return;
    }

    // Group messages & recalls (`cmd = 521`, `sub_cmd = 0`)
    if version == 1 && cmd == 521 && sub_cmd == 0 {
        if let Ok(decoded) = unpack_push_envelope(envelope, cipher_key) {
            if let Some(msgs) = decoded
                .get("data")
                .and_then(|d| d.get("groupMsgs"))
                .and_then(Value::as_array)
            {
                for m in msgs {
                    if is_recall_entry(m) {
                        let notice =
                            RecallNotice::from_wire(own_uid, ChannelKind::Group, m.clone());
                        if !notice.is_self || allow_self {
                            let _ =
                                events_tx.send(RealtimeEvent::MessageRecalled(Box::new(notice)));
                        }
                    } else {
                        let msg =
                            IncomingMessage::from_wire(own_uid, ChannelKind::Group, m.clone());
                        if !msg.is_self || allow_self {
                            let _ = events_tx.send(RealtimeEvent::MessageReceived(Box::new(msg)));
                        }
                    }
                }
            }
        }
        return;
    }

    // Control frames (`cmd = 601`, `sub_cmd = 0`): file_done, group events, friend events
    if version == 1 && cmd == 601 && sub_cmd == 0 {
        if let Ok(decoded) = unpack_push_envelope(envelope, cipher_key) {
            if let Some(controls) = decoded
                .get("data")
                .and_then(|d| d.get("controls"))
                .and_then(Value::as_array)
            {
                for ctrl in controls {
                    let Some(content) = ctrl.get("content") else {
                        continue;
                    };
                    let act_type = content
                        .get("act_type")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let act = content
                        .get("act")
                        .and_then(Value::as_str)
                        .unwrap_or_default();

                    match act_type {
                        "file_done" => {
                            let file_id = value_to_string(content.get("fileId"));
                            let file_url =
                                value_to_string(content.get("data").and_then(|d| d.get("url")));
                            let ready = UploadedMediaNotice { file_id, file_url };
                            session.fulfill_upload_waiter(ready.clone()).await;
                            let _ = events_tx.send(RealtimeEvent::UploadReady(ready));
                        }
                        "group" if act != "join_reject" => {
                            let data_val = parse_maybe_json_str(content.get("data"));
                            let group_id = value_to_string(
                                data_val.get("groupId").or_else(|| content.get("groupId")),
                            );
                            let _ = events_tx.send(RealtimeEvent::GroupActivity(GroupNotice {
                                action: act.to_owned(),
                                group_id,
                                data: data_val,
                            }));
                        }
                        "fr" if act != "req" => {
                            let data_val = parse_maybe_json_str(content.get("data"));
                            let _ = events_tx.send(RealtimeEvent::FriendActivity(FriendNotice {
                                action: act.to_owned(),
                                data: data_val,
                            }));
                        }
                        _ => {}
                    }
                }
            }
        }
        return;
    }

    // Reactions (`cmd = 612`)
    if cmd == 612 {
        if let Ok(decoded) = unpack_push_envelope(envelope, cipher_key) {
            if let Some(data) = decoded.get("data") {
                emit_reactions(
                    own_uid,
                    allow_self,
                    data.get("reacts"),
                    ChannelKind::Direct,
                    events_tx,
                );
                emit_reactions(
                    own_uid,
                    allow_self,
                    data.get("reactGroups"),
                    ChannelKind::Group,
                    events_tx,
                );
            }
        }
        return;
    }

    // Typing indicators (`cmd = 602`, `sub_cmd = 0`)
    if cmd == 602 && sub_cmd == 0 {
        if let Ok(decoded) = unpack_push_envelope(envelope, cipher_key) {
            if let Some(actions) = decoded
                .get("data")
                .and_then(|d| d.get("actions"))
                .and_then(Value::as_array)
            {
                for act_obj in actions {
                    if act_obj.get("act_type").and_then(Value::as_str) != Some("typing") {
                        continue;
                    }
                    let act_kind = act_obj
                        .get("act")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let raw_fragment = act_obj
                        .get("data")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let wrapped = format!("{{{raw_fragment}}}");
                    if let Ok(parsed) = serde_json::from_str::<Value>(&wrapped) {
                        let uid = value_to_string(parsed.get("uid"));
                        if act_kind == "gtyping" {
                            let gid = value_to_string(parsed.get("gid"));
                            let _ = events_tx.send(RealtimeEvent::TypingChanged(TypingNotice {
                                peer: Peer::group(gid),
                                user_id: uid,
                            }));
                        } else if act_kind == "typing" {
                            let _ = events_tx.send(RealtimeEvent::TypingChanged(TypingNotice {
                                peer: Peer::user(uid.clone()),
                                user_id: uid,
                            }));
                        }
                    }
                }
            }
        }
    }
}

fn is_recall_entry(msg: &Value) -> bool {
    msg.get("content")
        .and_then(Value::as_object)
        .map(|obj| obj.contains_key("deleteMsg"))
        .unwrap_or(false)
}

fn parse_maybe_json_str(val: Option<&Value>) -> Value {
    match val {
        Some(Value::String(s)) => {
            serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.clone()))
        }
        Some(other) => other.clone(),
        None => Value::Null,
    }
}

fn emit_reactions(
    own_uid: &str,
    allow_self: bool,
    arr_opt: Option<&Value>,
    kind: ChannelKind,
    events_tx: &broadcast::Sender<RealtimeEvent>,
) {
    let Some(items) = arr_opt.and_then(Value::as_array) else {
        return;
    };
    for r in items {
        let raw_from = value_to_string(r.get("uidFrom"));
        let raw_to = value_to_string(r.get("idTo"));
        let is_self = raw_from == "0" || raw_from == own_uid;
        if is_self && !allow_self {
            continue;
        }
        let sender_id = if raw_from == "0" {
            own_uid.to_owned()
        } else {
            raw_from
        };
        let peer_id = match kind {
            ChannelKind::Direct => {
                if is_self {
                    raw_to
                } else {
                    sender_id.clone()
                }
            }
            ChannelKind::Group => raw_to,
        };
        let content_val = parse_maybe_json_str(r.get("content"));
        let icon = value_to_string(content_val.get("rIcon"));
        let _ = events_tx.send(RealtimeEvent::ReactionChanged(Box::new(ReactionNotice {
            peer: Peer { id: peer_id, kind },
            sender_id,
            msg_id: value_to_string(r.get("msgId")),
            icon,
            is_self,
            raw: r.clone(),
        })));
    }
}
