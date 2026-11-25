//! Asynchronous QR authentication state machine against `id.zalo.me`.

use std::{path::Path, time::Duration};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, REFERER, USER_AGENT,
};
use serde::Deserialize;
use tokio::time::timeout;

use crate::{
    auth::CookieRecord,
    error::{ZaloxError, ZaloxResult},
    transport::HttpGateway,
};

const LOGIN_PORTAL_URL: &str = "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F";
const LOGIN_INFO_URL: &str = "https://id.zalo.me/account/logininfo";
const QR_GENERATE_URL: &str = "https://id.zalo.me/account/authen/qr/generate";
const QR_WAIT_SCAN_URL: &str = "https://id.zalo.me/account/authen/qr/waiting-scan";
const QR_WAIT_CONFIRM_URL: &str = "https://id.zalo.me/account/authen/qr/waiting-confirm";
const CHECK_SESSION_FALLBACK: &str =
    "https://id.zalo.me/account/checksession?continue=https%3A%2F%2Fchat.zalo.me%2Findex.html";
const JR_USERINFO_URL: &str = "https://jr.chat.zalo.me/jr/userinfo";
const CONTINUE_TARGET: &str = "https://chat.zalo.me/";

/// Lifecycle events emitted during an interactive QR login session.
#[derive(Debug, Clone)]
pub enum QrAuthEvent {
    /// A QR challenge image has been generated (initial or second-factor scan).
    QrReady {
        code: String,
        png_bytes: Vec<u8>,
        png_base64: String,
        is_second_factor: bool,
    },
    /// User scanned the QR code on mobile; waiting for mobile confirmation tap.
    Scanned {
        display_name: String,
        avatar_url: String,
    },
    /// Login succeeded and session cookies have been established.
    Authenticated {
        display_name: String,
        avatar_url: String,
    },
}

impl QrAuthEvent {
    /// Convenience helper to write the QR PNG bytes to disk when matching `QrReady`.
    pub async fn write_qr_png_if_ready(&self, path: impl AsRef<Path>) -> ZaloxResult<bool> {
        if let Self::QrReady { png_bytes, .. } = self {
            tokio::fs::write(path, png_bytes).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Final output of a completed QR authentication exchange.
#[derive(Debug, Clone)]
pub struct QrLoginOutcome {
    pub display_name: String,
    pub avatar_url: String,
    pub cookies: Vec<CookieRecord>,
}

#[derive(Debug, Deserialize)]
struct PortalEnvelope<T> {
    #[serde(default)]
    error_code: i64,
    #[serde(default)]
    error_message: String,
    data: Option<T>,
}

#[derive(Debug, Clone, Deserialize)]
struct QrGenData {
    code: String,
    image: String,
}

#[derive(Debug, Clone, Deserialize)]
struct QrScanData {
    #[serde(default)]
    avatar: String,
    #[serde(default)]
    display_name: String,
    status: Option<i64>,
    code: Option<String>,
    image: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct QrConfirmData {
    url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JrUserData {
    #[serde(default)]
    logged: bool,
    #[serde(default)]
    info: JrProfile,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct JrProfile {
    #[serde(default)]
    name: String,
    #[serde(default)]
    avatar: String,
}

/// Executes the full multi-step QR login flow on `gateway`, invoking `on_event` at each stage.
pub async fn execute_qr_login<F>(
    gateway: &HttpGateway,
    mut on_event: F,
) -> ZaloxResult<QrLoginOutcome>
where
    F: FnMut(QrAuthEvent),
{
    let portal_version = fetch_portal_version(gateway).await?;
    warm_login_info(gateway, &portal_version).await?;

    let initial_qr = request_qr_challenge(gateway, &portal_version).await?;
    let mut active_code = initial_qr.code;
    let mut active_image = initial_qr.image;
    let mut second_factor = false;

    let scanned = loop {
        let clean_b64 = strip_data_uri_prefix(&active_image).to_owned();
        let png_bytes = B64
            .decode(&clean_b64)
            .map_err(|e| ZaloxError::QrAuth(format!("Invalid QR PNG base64: {e}")))?;

        on_event(QrAuthEvent::QrReady {
            code: active_code.clone(),
            png_bytes,
            png_base64: clean_b64,
            is_second_factor: second_factor,
        });

        let scan_res = timeout(
            Duration::from_secs(105),
            poll_waiting_scan(gateway, &portal_version, &active_code),
        )
        .await
        .map_err(|_| ZaloxError::QrAuth("QR code expired before being scanned".into()))??;

        match scan_res.status {
            Some(5) => {
                return Err(ZaloxError::QrAuth(
                    "Zalo rejected QR scan (status = 5)".into(),
                ));
            }
            Some(4) => {
                // Multi-layer second QR scan requested by Zalo security
                active_code = scan_res.code.ok_or_else(|| {
                    ZaloxError::QrAuth("Second scan requested without new QR code".into())
                })?;
                active_image = scan_res.image.unwrap_or_default();
                second_factor = true;
            }
            _ => break scan_res,
        }
    };

    on_event(QrAuthEvent::Scanned {
        display_name: scanned.display_name.clone(),
        avatar_url: scanned.avatar.clone(),
    });

    let confirm_env = timeout(
        Duration::from_secs(105),
        poll_waiting_confirm(gateway, &portal_version, &active_code),
    )
    .await
    .map_err(|_| ZaloxError::QrAuth("Timed out waiting for mobile confirmation".into()))??;

    match confirm_env.error_code {
        0 => {}
        -13 => return Err(ZaloxError::QrDeclined),
        -14 => {
            return Err(ZaloxError::QrAuth(
                "QR session expired during confirmation".into(),
            ))
        }
        other => {
            return Err(ZaloxError::QrAuth(format!(
                "QR confirmation error ({other}): {}",
                confirm_env.error_message
            )))
        }
    }

    let check_url = confirm_env
        .data
        .and_then(|d| d.url)
        .unwrap_or_else(|| CHECK_SESSION_FALLBACK.to_owned());

    finalize_web_session(gateway, &check_url).await?;
    let profile = verify_jr_userinfo(gateway).await?;

    on_event(QrAuthEvent::Authenticated {
        display_name: profile.name.clone(),
        avatar_url: profile.avatar.clone(),
    });

    let cookies = gateway.export_cookies()?;
    Ok(QrLoginOutcome {
        display_name: profile.name,
        avatar_url: profile.avatar,
        cookies,
    })
}

fn portal_xhr_headers(ua: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(ACCEPT, HeaderValue::from_static("*/*"));
    h.insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static("vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7"),
    );
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    h.insert(REFERER, HeaderValue::from_static(LOGIN_PORTAL_URL));
    if let Ok(v) = HeaderValue::from_str(ua) {
        h.insert(USER_AGENT, v);
    }
    h
}

async fn fetch_portal_version(gateway: &HttpGateway) -> ZaloxResult<String> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert(REFERER, HeaderValue::from_static(CONTINUE_TARGET));
    if let Ok(v) = HeaderValue::from_str(gateway.user_agent()) {
        headers.insert(USER_AGENT, v);
    }

    let html = gateway
        .client()
        .get(LOGIN_PORTAL_URL)
        .headers(headers)
        .send()
        .await?
        .text()
        .await?;

    // Extract version from `https://stc-zlogin.zdn.vn/main-<ver>.js`
    if let Some(pos) = html.find("stc-zlogin.zdn.vn/main-") {
        let tail = &html[pos + "stc-zlogin.zdn.vn/main-".len()..];
        if let Some(js_end) = tail.find(".js") {
            let ver = &tail[..js_end];
            if !ver.is_empty() && ver.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return Ok(ver.to_owned());
            }
        }
    }
    Err(ZaloxError::QrAuth(
        "Could not locate stc-zlogin version script on id.zalo.me".into(),
    ))
}

async fn warm_login_info(gateway: &HttpGateway, version: &str) -> ZaloxResult<()> {
    let _ = gateway
        .client()
        .post(LOGIN_INFO_URL)
        .headers(portal_xhr_headers(gateway.user_agent()))
        .form(&[("continue", CONTINUE_TARGET), ("v", version)])
        .send()
        .await?;
    Ok(())
}

async fn request_qr_challenge(gateway: &HttpGateway, version: &str) -> ZaloxResult<QrGenData> {
    let resp: PortalEnvelope<QrGenData> = gateway
        .client()
        .post(QR_GENERATE_URL)
        .headers(portal_xhr_headers(gateway.user_agent()))
        .form(&[
            ("cliGenQR", "0"),
            ("continue", CONTINUE_TARGET),
            ("v", version),
        ])
        .send()
        .await?
        .json()
        .await?;

    resp.data.ok_or_else(|| {
        ZaloxError::QrAuth(format!(
            "Failed to generate QR code (code {}): {}",
            resp.error_code, resp.error_message
        ))
    })
}

async fn poll_waiting_scan(
    gateway: &HttpGateway,
    version: &str,
    code: &str,
) -> ZaloxResult<QrScanData> {
    loop {
        let response = gateway
            .client()
            .post(QR_WAIT_SCAN_URL)
            .headers(portal_xhr_headers(gateway.user_agent()))
            .form(&[
                ("code", code),
                ("continue", CONTINUE_TARGET),
                ("v", version),
            ])
            .send()
            .await?;

        let status_code = response.status().as_u16();
        if status_code == 502 || status_code == 504 {
            continue;
        }

        let env: PortalEnvelope<QrScanData> = response.json().await?;
        if env.error_code == 8 {
            continue;
        }
        return env.data.ok_or_else(|| {
            ZaloxError::QrAuth(format!(
                "QR scan polling failed (code {}): {}",
                env.error_code, env.error_message
            ))
        });
    }
}

async fn poll_waiting_confirm(
    gateway: &HttpGateway,
    version: &str,
    code: &str,
) -> ZaloxResult<PortalEnvelope<QrConfirmData>> {
    loop {
        let response = gateway
            .client()
            .post(QR_WAIT_CONFIRM_URL)
            .headers(portal_xhr_headers(gateway.user_agent()))
            .form(&[
                ("code", code),
                ("continue", CONTINUE_TARGET),
                ("v", version),
            ])
            .send()
            .await?;

        let status_code = response.status().as_u16();
        if status_code == 502 || status_code == 504 {
            continue;
        }

        let env: PortalEnvelope<QrConfirmData> = response.json().await?;
        if env.error_code == 8 {
            continue;
        }
        return Ok(env);
    }
}

async fn finalize_web_session(gateway: &HttpGateway, check_url: &str) -> ZaloxResult<()> {
    let mut headers = HeaderMap::new();
    headers.insert(REFERER, HeaderValue::from_static("https://id.zalo.me/"));
    if let Ok(v) = HeaderValue::from_str(gateway.user_agent()) {
        headers.insert(USER_AGENT, v);
    }

    let _ = gateway
        .client()
        .get(check_url)
        .headers(headers)
        .send()
        .await?;
    Ok(())
}

async fn verify_jr_userinfo(gateway: &HttpGateway) -> ZaloxResult<JrProfile> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(REFERER, HeaderValue::from_static(CONTINUE_TARGET));
    if let Ok(v) = HeaderValue::from_str(gateway.user_agent()) {
        headers.insert(USER_AGENT, v);
    }

    let env: PortalEnvelope<JrUserData> = gateway
        .client()
        .get(JR_USERINFO_URL)
        .headers(headers)
        .send()
        .await?
        .json()
        .await?;

    let user = env
        .data
        .ok_or_else(|| ZaloxError::QrAuth("Missing data in jr/userinfo check".into()))?;
    if !user.logged {
        return Err(ZaloxError::QrAuth(
            "jr/userinfo reported session is not logged in".into(),
        ));
    }
    Ok(user.info)
}

fn strip_data_uri_prefix(raw: &str) -> &str {
    raw.strip_prefix("data:image/png;base64,").unwrap_or(raw)
}
