//! Cryptographic primitives for session sealing, binary WebSocket framing,
//! and local encrypted credential storage.

pub mod frame_codec;
pub mod session_codec;
pub mod vault;

pub use frame_codec::{unpack_push_envelope, WireFrame, WireHeader};
pub use session_codec::{
    compute_request_mac, generate_device_imei, HandshakeTicket, SessionCipher,
};
pub use vault::SessionVault;
