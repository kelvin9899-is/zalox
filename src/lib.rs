//! # `zalox` — Pure-Rust Async Zalo SDK, Real-Time Engine & Bot Toolkit
//!
//! `zalox` is a standalone, clean-room Rust SDK for building personal and group
//! automation, AI assistants, and payment-integrated chatbots on Zalo without
//! external JavaScript/Python runtimes or native C/C++ image libraries (`sharp` / OpenSSL).
//!
//! ## Core Capabilities
//! - **100% Pure-Rust TLS & Crypto**: Powered by `rustls`, AES-CBC, AES-GCM (16-byte IV/AAD), and Zlib/Deflate.
//! - **Interactive QR Login & `ZLX1` Encrypted Vault**: Authenticate once via QR, persist credentials encrypted with `PBKDF2-HMAC-SHA256` + `AES-256-GCM`.
//! - **Anti-Ban `TrafficPacer`**: Built-in outbound request spacing + randomized human jitter.
//! - **Domain-Driven Service Handles**: `session.messaging()`, `session.contacts()`, `session.groups()`, `session.media()`.
//! - **Declarative `BotRouter`**: Prefix commands, shared state (`Arc<S>`), auto-typing indicators, and AI fallback handlers.
//! - **Vietnam Product Ecosystem**: Offline EMVCo **VietQR** generator (`CRC-16/CCITT-FALSE`), **payOS** & **SePay** constant-time webhook verifiers, and **Groq / Gemini / OpenRouter** AI bridge.

pub mod auth;
pub mod bot;
pub mod cipher;
pub mod ecosystem;
pub mod error;
pub mod realtime;
pub mod services;
pub mod session;
pub mod transport;
pub mod types;

pub use auth::{AuthCredentials, CookieRecord, QrAuthEvent};
pub use bot::{BotContext, BotRouter};
pub use cipher::SessionVault;
pub use error::{ZaloxError, ZaloxResult};
pub use realtime::{EventStreamConfig, IncomingMessage, RealtimeEvent, RealtimeHandle};
pub use services::{
    MediaSource, MessageDraft, MessageReceipt, MessageUrgency, PollBlueprint, ReactionKind,
    TextDecoration,
};
pub use session::{ZaloxBuilder, ZaloxClient, ZaloxSession};
pub use transport::PacingPolicy;
pub use types::{AvatarPreset, ChannelKind, Peer};

/// Ergonomic imports for most `zalox` applications.
pub mod prelude {
    pub use crate::{
        auth::{AuthCredentials, QrAuthEvent},
        bot::{BotContext, BotRouter},
        ecosystem::{LlmBridge, LlmProvider, VietQrOrder, VnBank},
        error::{ZaloxError, ZaloxResult},
        realtime::{IncomingMessage, RealtimeEvent},
        services::{MediaSource, MessageUrgency, PollBlueprint, ReactionKind, TextDecoration},
        session::{ZaloxClient, ZaloxSession},
        transport::PacingPolicy,
        types::{AvatarPreset, ChannelKind, Peer},
    };
}
