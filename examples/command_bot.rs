//! Example 2: Prefix-based Zalo Bot using `BotRouter` with reactions, rich-text, and VietQR.
//!
//! Run with:
//! ```bash
//! ZALOX_VAULT_KEY="your-secret" cargo run --example command_bot
//! ```

use zalox::prelude::*;

#[tokio::main]
async fn main() -> ZaloxResult<()> {
    let vault_key =
        std::env::var("ZALOX_VAULT_KEY").unwrap_or_else(|_| "demo-local-passphrase".into());
    let client = ZaloxClient::builder()
        .pacing(PacingPolicy::balanced())
        .build();

    let session = client.login_with_vault("account.zlx", &vault_key).await?;
    println!("🤖 Bot đã sẵn sàng trên UID {} (prefix `!`)", session.uid());

    let router = BotRouter::new("!")
        .command("ping", |ctx, _args| async move {
            ctx.react(ReactionKind::Heart).await?;
            ctx.quote_reply("🏓 Pong! Động cơ Pure-Rust `zalox` đang hoạt động mượt mà.").await?;
            Ok(())
        })
        .command("qr", |ctx, args| async move {
            let amount: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(50_000);
            let memo = args.get(1).cloned().unwrap_or_else(|| "THANHTOAN".into());

            let order = VietQrOrder::new(VnBank::MBBank, "0987654321")
                .amount(amount)
                .memo(&memo)
                .holder_name("NGUYEN VAN A");

            let qr_url = order.to_vietqr_image_url();
            let emv_raw = order.to_emvco_payload()?;
            ctx.quote_reply(format!(
                "💳 Mã thanh toán VietQR ({amount} VND - {memo}):\n🔗 Ảnh QR: {qr_url}\n📦 Chuỗi EMVCo offline: {emv_raw}"
            ))
            .await?;
            Ok(())
        });

    session.run_bot(router).await
}
