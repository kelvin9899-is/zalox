//! Built-in 3rd-party ecosystem connectors for building complete commercial products:
//! - `vietqr`: 100% offline Pure-Rust EMVCo VietQR payload & terminal QR builder.
//! - `webhook`: Constant-time HMAC-SHA256 webhook verifiers for **payOS** & **SePay**.
//! - `ai_bridge`: Lightweight async client for OpenAI-compatible (Groq/OpenRouter) & Gemini LLMs.

pub mod ai_bridge;
pub mod vietqr;
pub mod webhook;

pub use ai_bridge::{ChatTurn, LlmBridge, LlmProvider};
pub use vietqr::{crc16_ccitt_false, VietQrOrder, VnBank};
pub use webhook::{verify_payos_signature, verify_sepay_apikey, SepayWebhookEvent};
