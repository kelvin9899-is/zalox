# 🦀 `zalox` — Pure-Rust Async Zalo SDK, Real-Time Engine & Bot Toolkit

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Pure Rust TLS](https://img.shields.io/badge/TLS-rustls%20(Zero%20OpenSSL)-success.svg)](#)

**`zalox`** là bộ SDK bất đồng bộ viết **100% bằng Pure Rust** dành cho việc xây dựng hệ thống tự động hóa, trợ lý AI và chatbot thương mại trên Zalo (hỗ trợ cả hội thoại cá nhân 1-1 lẫn nhóm chat).

Khác biệt hoàn toàn với các thư viện viết bằng JavaScript hay Python phải kéo theo runtime cồng kềnh hoặc thư viện C++ xử lý ảnh nặng nề (`sharp`/`libvips`, OpenSSL), `zalox` biên dịch ra **một file thực thi độc lập duy nhất (~6–10 MB)**, sử dụng RAM siêu thấp (~12 MB) và tích hợp sẵn các mảnh ghép thực chiến cho sản phẩm tại Việt Nam.

---

## ✨ Điểm Khác Biệt Cốt Lõi

- **Kiến trúc Domain-Driven chuẩn Rust**: Thay vì gom hàng trăm hàm rời rạc vào một object phẳng, `zalox` phân tách mạch lạc thành các phân hệ Fluent Builder:
  - `session.messaging()` — Soạn thảo tin nhắn định dạng đậm/nghiêng/màu sắc, trích dẫn (`quote`), nhắc tên (`@mention` / `@All`), thu hồi (`recall`), chuyển tiếp hàng loạt, thả cảm xúc (`ReactionKind`), gửi nhãn dán (`sticker`).
  - `session.contacts()` — Tìm kiếm qua số điện thoại, lấy hồ sơ chi tiết, danh sách bạn bè, lời mời kết bạn, đặt biệt danh.
  - `session.groups()` — Liệt kê nhóm, thông tin nhóm, tạo nhóm mới, thêm/mời thành viên, đổi tên nhóm, tạo bình chọn (`PollBlueprint`).
  - `session.media()` — Bộ đọc kích thước ảnh **Pure-Rust Zero-Decode** (`PNG`, `JPEG`, `GIF`, `WebP`) không cần giải mã điểm ảnh hay cài `sharp`, hỗ trợ tải lên phân mảnh (chunked upload).
- **Kho Phiên Mã Hóa `ZLX1` (`SessionVault`)**: Đăng nhập quét QR một lần duy nhất, lưu trữ thông tin phiên xuống đĩa bằng `PBKDF2-HMAC-SHA256` (100.000 vòng) + `AES-256-GCM`, tuyệt đối không phơi bày Cookie dạng văn bản thuần.
- **Bộ Điều Nhịp Chống Khóa Tài Khoản (`TrafficPacer`)**: Tích hợp sẵn cơ chế giãn cách kèm độ trễ ngẫu nhiên mô phỏng thao tác người thật (`PacingPolicy::human_like()`).
- **Luồng Sự Kiện Nhị Phân Thời Gian Thực (`RealtimeHandle`)**: Tự động giải mã gói nhị phân 4-byte (`AES-GCM` 16-byte IV/AAD + `Zlib/Deflate`), tự động xoay vòng máy chủ WebSocket khi rớt mạng và phát nhịp tim giữ kết nối.
- **Bộ Định Tuyến Bot (`BotRouter<S>`)**: Khai báo lệnh theo tiền tố (`!ping`, `/qr`), chia sẻ trạng thái đa luồng `Arc<S>`, tự động bật trạng thái *"đang soạn tin..."* trước khi phản hồi.
- **Hệ Sinh Thái Sản Phẩm Việt Nam (`zalox::ecosystem`)**:
  - **VietQR Offline (`VietQrOrder`)**: Tự sinh chuỗi chuẩn EMVCo NAPAS 24/7 (`A000000727` + `CRC-16/CCITT-FALSE`), vẽ mã QR ngay trên Terminal hoặc xuất link ảnh QR động mà không phụ thuộc dịch vụ ngoài.
  - **Xác Thực Webhook Thanh Toán**: Hàm kiểm tra chữ ký `HMAC-SHA256` chống tấn công thời gian (constant-time) cho **payOS** và **SePay**.
  - **Cầu Nối AI (`LlmBridge`)**: Kết nối gọn nhẹ tới **Groq**, **OpenRouter**, **OpenAI** và **Google Gemini**.

---

## 📦 Cài Đặt

Thêm `zalox` vào `Cargo.toml` của dự án:

```toml
[dependencies]
zalox = { git = "https://github.com/kelvin9899-is/zalox.git" }
tokio = { version = "1", features = ["full"] }
```

---

## 🚀 Bắt Đầu Nhanh

### 1. Đăng nhập mã QR & Lưu phiên mã hóa `ZLX1`

```rust
use std::path::Path;
use zalox::prelude::*;

#[tokio::main]
async fn main() -> ZaloxResult<()> {
    let client = ZaloxClient::builder()
        .pacing(PacingPolicy::human_like())
        .build();

    let session = if Path::new("account.zlx").exists() {
        client.login_with_vault("account.zlx", "mat-khau-kho-cua-ban").await?
    } else {
        let s = client
            .login_with_qr(|ev| {
                if let QrAuthEvent::QrReady { png_bytes, .. } = ev {
                    let _ = std::fs::write("qr.png", png_bytes);
                    println!("Quét file qr.png bằng ứng dụng Zalo trên điện thoại!");
                }
            })
            .await?;
        s.save_vault("account.zlx", "mat-khau-kho-cua-ban").await?;
        s
    };

    println!("Đăng nhập thành công UID: {}", session.uid());
    Ok(())
}
```

### 2. Khởi chạy Chatbot kèm VietQR bằng `BotRouter`

```rust
use zalox::prelude::*;

#[tokio::main]
async fn main() -> ZaloxResult<()> {
    let client = ZaloxClient::default();
    let session = client.login_with_vault("account.zlx", "mat-khau-kho-cua-ban").await?;

    let router = BotRouter::new("!")
        .command("ping", |ctx, _args| async move {
            ctx.react(ReactionKind::Heart).await?;
            ctx.quote_reply("🏓 Pong từ động cơ Pure-Rust zalox!").await?;
            Ok(())
        })
        .command("pay", |ctx, args| async move {
            let vnd: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(100_000);
            let qr = VietQrOrder::new(VnBank::MBBank, "0987654321")
                .amount(vnd)
                .memo("THANHTOAN VIP");
            ctx.quote_reply(format!("Quét mã VietQR: {}", qr.to_vietqr_image_url())).await?;
            Ok(())
        });

    session.run_bot(router).await
}
```

### 3. Gửi tin nhắn định dạng Rich-Text theo phong cách Fluent Builder

```rust
session
    .messaging()
    .compose(Peer::group("GROUP_ID"))
    .text("Thông báo quan trọng cho cả nhóm @All!")
    .bold(0..20)
    .mention_all(33, 4)
    .urgency(MessageUrgency::Important)
    .send()
    .await?;
```

---

## 🗂️ Cấu Trúc Thư Mục

```text
zalox/
├── src/
│   ├── auth/         # Luồng xác thực QR & định dạng Credentials đa năng
│   ├── bot/          # Bộ định tuyến lệnh bất đồng bộ BotRouter<S>
│   ├── cipher/       # AES-CBC, ZCID, Frame WebSocket AES-GCM 16B & Kho khóa ZLX1
│   ├── ecosystem/    # VietQR EMVCo offline, Webhook payOS/SePay, Cầu nối AI LLM
│   ├── realtime/     # Giám sát kết nối WebSocket, xoay vòng endpoint & sự kiện
│   ├── services/     # Messaging, Contacts, Groups, Media & Pure-Rust Image Probe
│   ├── transport/    # HttpGateway, dò tự động zpw_ver & TrafficPacer chống khóa nick
│   ├── error.rs      # Phân loại lỗi tường minh với thiserror
│   ├── session.rs    # ZaloxBuilder, ZaloxClient & ZaloxSession (Arc-backed)
│   └── types.rs      # Kiểu miền dùng chung (Peer, ServiceDirectory, Limits)
└── examples/
    ├── qr_vault_login.rs
    ├── command_bot.rs
    └── vietqr_ai_assistant.rs
```

---

## ⚠️ Lưu Ý An Toàn & Miễn Trừ Trách Nhiệm

1. **Dự án độc lập phi chính thức**: `zalox` là bộ công cụ nghiên cứu & tự động hóa giao thức Web độc lập, không liên kết hoặc được bảo trợ bởi VNG / Zalo Group.
2. **Bảo vệ tài khoản cá nhân**:
   - Không mở song song `chat.zalo.me` trên trình duyệt của cùng tài khoản khi đang chạy `subscribe_events()` / `run_bot()`.
   - Luôn bật `PacingPolicy::balanced()` hoặc `PacingPolicy::human_like()`, tránh gửi tin nhắn quảng cáo hàng loạt tới người lạ.
   - Với các hệ thống CSKH quy mô doanh nghiệp cần cam kết SLA chính thống, hãy kết hợp thêm Zalo Official Account (OA) / ZNS.

---

## 📄 Giấy Phép (License)

Phân phối kép dưới giấy phép **[MIT](LICENSE-MIT)** hoặc **[Apache-2.0](LICENSE-APACHE)** tùy theo lựa chọn của bạn (chuẩn hệ sinh thái Rust).
