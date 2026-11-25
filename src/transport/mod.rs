//! Cookie-aware HTTP gateway, API version discovery, and anti-ban traffic pacing.

pub mod http;
pub mod pacing;

pub use http::{ApiSignature, HttpGateway, DEFAULT_API_TYPE, DEFAULT_API_VERSION};
pub use pacing::{PacingPolicy, TrafficPacer};
