//! Authentication credentials, browser cookie interoperability, and QR login flow.

pub mod credentials;
pub mod qr_flow;

pub use credentials::{AuthCredentials, CookieInput, CookieRecord};
pub use qr_flow::{execute_qr_login, QrAuthEvent, QrLoginOutcome};
