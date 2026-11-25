//! Persistent binary WebSocket event listener with automatic endpoint rotation,
//! 3-minute heartbeat, and strongly-typed real-time events.

pub mod events;
pub mod stream;

pub use events::{
    FriendNotice, GroupNotice, IncomingMessage, MessageBody, QuoteMetadata, ReactionNotice,
    RealtimeEvent, RecallNotice, TypingNotice,
};
pub use stream::{EventStreamConfig, RealtimeHandle};
