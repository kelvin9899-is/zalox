//! Declarative prefix-command router (`!help`, `/pay 50000`) with shared `Arc<S>` state
//! and optional human-like typing indicator before replies.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use tokio::sync::broadcast::error::RecvError;

use crate::{
    error::ZaloxResult,
    realtime::{IncomingMessage, RealtimeEvent},
    services::{MediaSource, MessageReceipt, ReactionKind},
    session::ZaloxSession,
};

type BoxHandlerFuture = Pin<Box<dyn Future<Output = ZaloxResult<()>> + Send>>;
type CommandCallback<S> = Arc<dyn Fn(BotContext<S>, Vec<String>) -> BoxHandlerFuture + Send + Sync>;
type FallbackCallback<S> = Arc<dyn Fn(BotContext<S>) -> BoxHandlerFuture + Send + Sync>;

/// Per-message execution context passed into every `BotRouter` command or fallback handler.
pub struct BotContext<S> {
    pub session: ZaloxSession,
    pub message: IncomingMessage,
    pub state: Arc<S>,
}

impl<S> Clone for BotContext<S> {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            message: self.message.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

impl<S> BotContext<S> {
    /// Sends a plain-text message to the same user/group thread.
    pub async fn reply(&self, text: impl Into<String>) -> ZaloxResult<MessageReceipt> {
        self.session
            .messaging()
            .send_text(self.message.peer.clone(), text)
            .await
    }

    /// Sends a quote-reply referencing the triggering message.
    pub async fn quote_reply(&self, text: impl Into<String>) -> ZaloxResult<MessageReceipt> {
        self.session
            .messaging()
            .quote_reply(&self.message, text)
            .await
    }

    /// Reacts to the triggering message with an icon (e.g., `ReactionKind::Heart`).
    pub async fn react(&self, kind: ReactionKind) -> ZaloxResult<()> {
        let _ = self
            .session
            .messaging()
            .react(
                self.message.peer.clone(),
                &self.message.msg_id,
                &self.message.cli_msg_id,
                kind,
            )
            .await?;
        Ok(())
    }

    /// Uploads and sends a photo (`png`/`jpg`/`webp`) to the active thread.
    pub async fn reply_photo(
        &self,
        source: MediaSource,
        caption: &str,
    ) -> ZaloxResult<MessageReceipt> {
        self.session
            .media()
            .send_photo(self.message.peer.clone(), source, caption, 0)
            .await
    }

    /// Emits a typing indicator to the active thread.
    pub async fn typing(&self) -> ZaloxResult<()> {
        let _ = self
            .session
            .messaging()
            .send_typing(self.message.peer.clone())
            .await?;
        Ok(())
    }
}

/// Asynchronous prefix-based command router for rapid Zalo chatbot creation.
pub struct BotRouter<S = ()> {
    prefix: String,
    state: Arc<S>,
    auto_typing: bool,
    commands: HashMap<String, CommandCallback<S>>,
    fallback: Option<FallbackCallback<S>>,
}

impl BotRouter<()> {
    /// Creates a stateless `BotRouter` matching commands starting with `prefix` (e.g., `"!"` or `"/"`).
    pub fn new(prefix: impl Into<String>) -> Self {
        Self::with_state(prefix, ())
    }
}

impl<S: Send + Sync + 'static> BotRouter<S> {
    /// Creates a stateful `BotRouter` sharing `state` across all concurrent command tasks.
    pub fn with_state(prefix: impl Into<String>, state: S) -> Self {
        Self {
            prefix: prefix.into(),
            state: Arc::new(state),
            auto_typing: true,
            commands: HashMap::new(),
            fallback: None,
        }
    }

    /// Enables or disables sending an automatic typing indicator before executing matched commands.
    pub fn auto_typing(mut self, enabled: bool) -> Self {
        self.auto_typing = enabled;
        self
    }

    /// Registers a case-insensitive command name (without the prefix, e.g. `"ping"` for `"!ping"`).
    pub fn command<F, Fut>(mut self, name: &str, handler: F) -> Self
    where
        F: Fn(BotContext<S>, Vec<String>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ZaloxResult<()>> + Send + 'static,
    {
        let key = name.trim().to_ascii_lowercase();
        self.commands
            .insert(key, Arc::new(move |ctx, args| Box::pin(handler(ctx, args))));
        self
    }

    /// Registers a fallback handler invoked for non-command text messages (ideal for LLM/AI chat).
    pub fn on_unmatched_text<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(BotContext<S>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ZaloxResult<()>> + Send + 'static,
    {
        self.fallback = Some(Arc::new(move |ctx| Box::pin(handler(ctx))));
        self
    }

    /// Subscribes to `session` real-time events and dispatches handlers concurrently.
    pub async fn serve(self, session: ZaloxSession) -> ZaloxResult<()> {
        let handle = session.subscribe_events()?;
        let mut rx = handle.receiver();
        let shared = Arc::new(self);

        loop {
            match rx.recv().await {
                Ok(RealtimeEvent::MessageReceived(msg)) => {
                    if msg.is_self {
                        continue;
                    }
                    let Some(text) = msg.text().map(str::trim) else {
                        continue;
                    };
                    if text.is_empty() {
                        continue;
                    }

                    let ctx = BotContext {
                        session: session.clone(),
                        message: (*msg).clone(),
                        state: Arc::clone(&shared.state),
                    };

                    if let Some(stripped) = text.strip_prefix(&shared.prefix) {
                        let mut parts = stripped.split_whitespace();
                        if let Some(raw_cmd) = parts.next() {
                            let cmd_key = raw_cmd.to_ascii_lowercase();
                            if let Some(cb) = shared.commands.get(&cmd_key).cloned() {
                                let args: Vec<String> = parts.map(str::to_owned).collect();
                                let send_typing = shared.auto_typing;
                                tokio::spawn(async move {
                                    if send_typing {
                                        let _ = ctx.typing().await;
                                    }
                                    if let Err(err) = cb(ctx, args).await {
                                        tracing::warn!(command = %cmd_key, error = %err, "Bot command handler error");
                                    }
                                });
                                continue;
                            }
                        }
                    }

                    if let Some(fb) = shared.fallback.clone() {
                        tokio::spawn(async move {
                            if let Err(err) = fb(ctx).await {
                                tracing::warn!(error = %err, "Bot fallback handler error");
                            }
                        });
                    }
                }
                Ok(RealtimeEvent::SessionDisplaced) => {
                    tracing::error!("Zalo WebSocket session was displaced by another login");
                    break;
                }
                Ok(_) => {}
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "Realtime event consumer lagged; continuing");
                }
                Err(RecvError::Closed) => break,
            }
        }
        Ok(())
    }
}
