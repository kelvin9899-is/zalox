//! Example 3: Offline VietQR EMVCo + PayOS/SePay Webhook + AI Assistant showcase.
//! Works immediately without needing a live Zalo login to inspect VietQR output!
//!
//! Run with:
//! ```bash
//! cargo run --example vietqr_ai_assistant
//! ```

use zalox::ecosystem::{verify_sepay_apikey, VietQrOrder, VnBank};
use zalox::error::ZaloxResult;

#[tokio::main]
async fn main() -> ZaloxResult<()> {
    let order = VietQrOrder::new(VnBank::Vietcombank, "0123456789")
        .amount(199_000)
        .memo("ZALOX PRO 101")
        .holder_name("CONG TY TNHH ZALOX");

    println!("=== 1. Chuỗi EMVCo NAPAS 24/7 (CRC-16/CCITT-FALSE Offline) ===");
    println!("{}\n", order.to_emvco_payload()?);

    println!("=== 2. Link ảnh QR nhanh ===");
    println!("{}\n", order.to_vietqr_image_url());

    println!("=== 3. Mã QR Unicode trực tiếp trên Terminal ===");
    println!("{}", order.render_terminal_qr()?);

    let ok = verify_sepay_apikey("Apikey sepay_secret_demo", "sepay_secret_demo");
    println!("=== 4. Kiểm tra chữ ký SePay constant-time: {ok} ===");

    Ok(())
}
