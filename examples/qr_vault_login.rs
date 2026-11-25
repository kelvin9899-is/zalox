//! Example 1: Authenticate via QR Code once and save an encrypted `ZLX1` session vault.
//!
//! Run with:
//! ```bash
//! cargo run --example qr_vault_login
//! ```

use std::path::Path;
use zalox::prelude::*;

const VAULT_FILE: &str = "account.zlx";

#[tokio::main]
async fn main() -> ZaloxResult<()> {
    let passphrase =
        std::env::var("ZALOX_VAULT_KEY").unwrap_or_else(|_| "demo-local-passphrase".into());
    let client = ZaloxClient::builder()
        .pacing(PacingPolicy::human_like())
        .build();

    let session = if Path::new(VAULT_FILE).exists() {
        println!("🔐 Đang khôi phục phiên từ kho mã hóa `{VAULT_FILE}`...");
        client.login_with_vault(VAULT_FILE, &passphrase).await?
    } else {
        println!("📱 Chưa có phiên lưu sẵn. Đang tạo mã QR đăng nhập...");
        let sess = client
            .login_with_qr(|event| match event {
                QrAuthEvent::QrReady {
                    png_bytes,
                    is_second_factor,
                    ..
                } => {
                    let filename = if is_second_factor { "qr_step2.png" } else { "qr.png" };
                    if std::fs::write(filename, &png_bytes).is_ok() {
                        println!("✅ Đã lưu mã QR tại `{filename}` — mở app Zalo trên điện thoại để quét!");
                    }
                }
                QrAuthEvent::Scanned { display_name, .. } => {
                    println!("👀 Đã quét bởi `{display_name}` — vui lòng bấm Xác nhận trên điện thoại...");
                }
                QrAuthEvent::Authenticated { display_name, .. } => {
                    println!("🎉 Xác thực thành công tài khoản: {display_name}");
                }
            })
            .await?;

        sess.save_vault(VAULT_FILE, &passphrase).await?;
        println!("💾 Đã mã hóa AES-256-GCM và lưu phiên vào `{VAULT_FILE}`!");
        sess
    };

    println!("🚀 Đang hoạt động với UID: {}", session.uid());
    Ok(())
}
