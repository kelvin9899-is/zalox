//! Constant-time webhook verification helpers for Vietnamese payment gateways (**payOS** & **SePay**).

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Standard SePay bank-transfer fluctuation webhook JSON payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SepayWebhookEvent {
    pub id: u64,
    #[serde(default)]
    pub gateway: String,
    #[serde(rename = "transactionDate", default)]
    pub transaction_date: String,
    #[serde(rename = "accountNumber", default)]
    pub account_number: String,
    pub code: Option<String>,
    #[serde(default)]
    pub content: String,
    #[serde(rename = "transferType", default)]
    pub transfer_type: String,
    #[serde(rename = "transferAmount", default)]
    pub transfer_amount: u64,
    #[serde(default)]
    pub accumulated: u64,
    #[serde(rename = "referenceCode", default)]
    pub reference_code: String,
    #[serde(default)]
    pub description: String,
}

impl SepayWebhookEvent {
    /// Returns `true` when this notification represents incoming money (`"in"`).
    pub fn is_inbound_credit(&self) -> bool {
        self.transfer_type.eq_ignore_ascii_case("in")
    }
}

/// Verifies SePay's `Authorization: Apikey <YOUR_SECRET>` header in constant time.
pub fn verify_sepay_apikey(authorization_header: &str, expected_apikey: &str) -> bool {
    if expected_apikey.is_empty() {
        return false;
    }
    let trimmed = authorization_header.trim();
    let candidate = trimmed
        .strip_prefix("Apikey ")
        .or_else(|| trimmed.strip_prefix("apikey "))
        .unwrap_or(trimmed);

    candidate
        .as_bytes()
        .ct_eq(expected_apikey.as_bytes())
        .into()
}

/// Verifies a **payOS** webhook signature (`HMAC-SHA256` over alphabetically sorted `key=value` pairs
/// of the `data` object) in constant time.
pub fn verify_payos_signature(data_obj: &Value, signature_hex: &str, checksum_key: &str) -> bool {
    let Some(map) = data_obj.as_object() else {
        return false;
    };
    let Ok(expected_sig) = hex::decode(signature_hex.trim()) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(checksum_key.as_bytes()) else {
        return false;
    };

    let mut sorted = BTreeMap::new();
    for (k, v) in map {
        let normalized_val = match v {
            Value::Null => String::new(),
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            complex => serde_json::to_string(complex).unwrap_or_default(),
        };
        sorted.insert(k.as_str(), normalized_val);
    }

    let canonical: String = sorted
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    mac.update(canonical.as_bytes());
    let computed = mac.finalize().into_bytes();
    computed.as_slice().ct_eq(expected_sig.as_slice()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_payos_hmac_and_rejects_tampering() {
        let secret = "my_payos_checksum_secret";
        let data = serde_json::json!({
            "orderCode": 123456,
            "amount": 50000,
            "description": "DH123456"
        });

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(b"amount=50000&description=DH123456&orderCode=123456");
        let valid_hex = hex::encode(mac.finalize().into_bytes());

        assert!(verify_payos_signature(&data, &valid_hex, secret));

        let tampered = serde_json::json!({
            "orderCode": 123456,
            "amount": 5000,
            "description": "DH123456"
        });
        assert!(!verify_payos_signature(&tampered, &valid_hex, secret));
    }

    #[test]
    fn verifies_sepay_apikey_header_safely() {
        assert!(verify_sepay_apikey("Apikey sk_live_999", "sk_live_999"));
        assert!(!verify_sepay_apikey("Apikey sk_live_000", "sk_live_999"));
    }
}
