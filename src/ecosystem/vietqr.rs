//! 100% Pure-Rust offline EMVCo NAPAS 247 VietQR generator (`A000000727` + CRC-16/CCITT-FALSE),
//! Unicode terminal QR renderer, and `img.vietqr.io` image URL builder.

use qrcode::{render::unicode, QrCode};
use serde::{Deserialize, Serialize};

use crate::error::{ZaloxError, ZaloxResult};

const NAPAS_GUID: &str = "A000000727";

/// Major Vietnamese bank BIN codes & short identifiers for NAPAS 24/7 VietQR transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VnBank {
    Vietcombank,
    VietinBank,
    BIDV,
    Agribank,
    MBBank,
    Techcombank,
    ACB,
    VPBank,
    TPBank,
    Sacombank,
    HDBank,
    VIB,
    SHB,
    MSB,
    OCB,
    SeABank,
    Eximbank,
    Cake,
    Timo,
    Custom {
        bin: &'static str,
        code: &'static str,
    },
}

impl VnBank {
    /// Returns the 6-digit NAPAS BIN (`9704xx`) and short bank slug.
    pub const fn metadata(&self) -> (&'static str, &'static str) {
        match self {
            Self::Vietcombank => ("970436", "VCB"),
            Self::VietinBank => ("970415", "ICB"),
            Self::BIDV => ("970418", "BIDV"),
            Self::Agribank => ("970405", "VBA"),
            Self::MBBank => ("970422", "MB"),
            Self::Techcombank => ("970407", "TCB"),
            Self::ACB => ("970416", "ACB"),
            Self::VPBank => ("970432", "VPB"),
            Self::TPBank => ("970423", "TPB"),
            Self::Sacombank => ("970403", "STB"),
            Self::HDBank => ("970437", "HDB"),
            Self::VIB => ("970441", "VIB"),
            Self::SHB => ("970443", "SHB"),
            Self::MSB => ("970426", "MSB"),
            Self::OCB => ("970448", "OCB"),
            Self::SeABank => ("970440", "SEAB"),
            Self::Eximbank => ("970431", "EIB"),
            Self::Cake => ("546034", "CAKE"),
            Self::Timo => ("963388", "TIMO"),
            Self::Custom { bin, code } => (bin, code),
        }
    }
}

/// Builder for generating dynamic or static VietQR payment strings and URLs.
#[derive(Debug, Clone)]
pub struct VietQrOrder {
    pub bank: VnBank,
    pub account_number: String,
    pub account_holder: Option<String>,
    pub amount_vnd: Option<u64>,
    pub memo: Option<String>,
}

impl VietQrOrder {
    pub fn new(bank: VnBank, account_number: impl Into<String>) -> Self {
        Self {
            bank,
            account_number: account_number.into(),
            account_holder: None,
            amount_vnd: None,
            memo: None,
        }
    }

    pub fn amount(mut self, vnd: u64) -> Self {
        self.amount_vnd = Some(vnd);
        self
    }

    pub fn memo(mut self, content: impl Into<String>) -> Self {
        self.memo = Some(content.into());
        self
    }

    pub fn holder_name(mut self, name: impl Into<String>) -> Self {
        self.account_holder = Some(name.into());
        self
    }

    /// Generates a 100% offline EMVCo-compliant VietQR raw payload string with `CRC-16/CCITT-FALSE`.
    pub fn to_emvco_payload(&self) -> ZaloxResult<String> {
        let acct = self.account_number.trim();
        if acct.is_empty() {
            return Err(ZaloxError::Ecosystem(
                "VietQR account_number cannot be empty".into(),
            ));
        }
        let (bin, _) = self.bank.metadata();

        // Merchant Account Information (Tag 38 -> NAPAS 24/7 Account Transfer QRIBFTTA)
        let beneficiary = format!("{}{}", tlv("00", bin), tlv("01", acct));
        let tag_38_inner = format!(
            "{}{}{}",
            tlv("00", NAPAS_GUID),
            tlv("01", &beneficiary),
            tlv("02", "QRIBFTTA")
        );

        let is_dynamic = self.amount_vnd.filter(|&a| a > 0).is_some()
            || self.memo.as_ref().is_some_and(|m| !m.trim().is_empty());

        let mut payload = String::with_capacity(180);
        payload.push_str(&tlv("00", "01")); // Payload Format Indicator
        payload.push_str(&tlv("01", if is_dynamic { "12" } else { "11" })); // Point of Initiation
        payload.push_str(&tlv("38", &tag_38_inner));
        payload.push_str(&tlv("53", "704")); // Currency VND (ISO 4217 = 704)

        if let Some(amt) = self.amount_vnd.filter(|&a| a > 0) {
            payload.push_str(&tlv("54", &amt.to_string()));
        }

        payload.push_str(&tlv("58", "VN")); // Country Code

        if let Some(ref memo) = self.memo {
            let clean = sanitize_ascii_memo(memo);
            if !clean.is_empty() {
                let tag_62_inner = tlv("08", &clean);
                payload.push_str(&tlv("62", &tag_62_inner));
            }
        }

        // Tag 63 (CRC, length 04)
        payload.push_str("6304");
        let crc = crc16_ccitt_false(payload.as_bytes());
        payload.push_str(&format!("{crc:04X}"));
        Ok(payload)
    }

    /// Renders the offline EMVCo VietQR string into compact Unicode half-blocks (`▀`/`▄`/`█`)
    /// for instant display in terminals or logs.
    pub fn render_terminal_qr(&self) -> ZaloxResult<String> {
        let emv = self.to_emvco_payload()?;
        let code = QrCode::new(emv.as_bytes())
            .map_err(|e| ZaloxError::Ecosystem(format!("QR matrix encoding failed: {e}")))?;
        Ok(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
    }

    /// Builds a ready-to-fetch `img.vietqr.io` PNG URL (`compact2` template) for sending in chat.
    pub fn to_vietqr_image_url(&self) -> String {
        let (bin, _) = self.bank.metadata();
        let mut url = format!(
            "https://img.vietqr.io/image/{}-{}-compact2.png",
            bin,
            urlencoding::encode(self.account_number.trim())
        );

        let mut qp = Vec::new();
        if let Some(amt) = self.amount_vnd.filter(|&a| a > 0) {
            qp.push(format!("amount={amt}"));
        }
        if let Some(ref memo) = self.memo {
            if !memo.trim().is_empty() {
                qp.push(format!("addInfo={}", urlencoding::encode(memo.trim())));
            }
        }
        if let Some(ref holder) = self.account_holder {
            if !holder.trim().is_empty() {
                qp.push(format!(
                    "accountName={}",
                    urlencoding::encode(holder.trim())
                ));
            }
        }
        if !qp.is_empty() {
            url.push('?');
            url.push_str(&qp.join("&"));
        }
        url
    }
}

fn tlv(tag: &str, value: &str) -> String {
    format!("{tag}{:02}{value}", value.len())
}

fn sanitize_ascii_memo(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .take(50)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Standard EMVCo `CRC-16/CCITT-FALSE` (`poly = 0x1021`, `init = 0xFFFF`, `xor_out = 0x0000`).
pub fn crc16_ccitt_false(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in bytes {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_matches_standard_check_vector() {
        // Standard check string "123456789" -> 0x29B1 for CRC-16/CCITT-FALSE
        assert_eq!(crc16_ccitt_false(b"123456789"), 0x29B1);
    }

    #[test]
    fn generates_valid_emvco_vietqr_and_terminal_matrix() {
        let order = VietQrOrder::new(VnBank::MBBank, "0987654321")
            .amount(150_000)
            .memo("DH1024");
        let emv = order.to_emvco_payload().unwrap();
        assert!(emv.starts_with("000201010212"));
        assert!(emv.contains("A000000727"));
        assert!(emv.contains("970422"));
        assert!(emv.contains("5406150000"));
        assert!(emv.contains("6304"));

        let qr_ascii = order.render_terminal_qr().unwrap();
        assert!(!qr_ascii.is_empty());
    }
}
