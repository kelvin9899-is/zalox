//! Cookie-aware HTTP client, dynamic Zalo Web bundle version detector,
//! and encrypted JSON envelope dispatcher.

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use reqwest::{
    header::{
        HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, ORIGIN, REFERER, USER_AGENT,
    },
    redirect::Policy,
    Client, Method,
};
use reqwest_cookie_store::{CookieStore, CookieStoreMutex};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::Mutex;
use url::Url;

use crate::{
    auth::CookieRecord,
    cipher::SessionCipher,
    error::{ZaloxError, ZaloxResult},
    transport::TrafficPacer,
};

pub const DEFAULT_API_TYPE: u32 = 30;
pub const DEFAULT_API_VERSION: u32 = 695;
pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0";

const ZALO_CHAT_ORIGIN: &str = "https://chat.zalo.me";
const ZALO_CHAT_REFERER: &str = "https://chat.zalo.me/";

/// Zalo Web client signature (`zpw_type` & `zpw_ver`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiSignature {
    pub api_type: u32,
    pub api_version: u32,
}

impl Default for ApiSignature {
    fn default() -> Self {
        Self {
            api_type: DEFAULT_API_TYPE,
            api_version: DEFAULT_API_VERSION,
        }
    }
}

fn bundle_version_cache() -> &'static Mutex<HashMap<String, ApiSignature>> {
    static CACHE: OnceLock<Mutex<HashMap<String, ApiSignature>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Shared HTTP gateway managing RFC-6265 cookies, headers, proxy, and pacing.
#[derive(Clone, Debug)]
pub struct HttpGateway {
    client: Client,
    cookie_jar: Arc<CookieStoreMutex>,
    user_agent: String,
    signature: ApiSignature,
    pacer: Arc<TrafficPacer>,
}

impl HttpGateway {
    /// Builds a new `HttpGateway` with an isolated cookie jar.
    pub fn new(
        user_agent: impl Into<String>,
        signature: ApiSignature,
        pacer: Arc<TrafficPacer>,
        proxy_url: Option<&str>,
    ) -> ZaloxResult<Self> {
        let ua = user_agent.into();
        let jar = Arc::new(CookieStoreMutex::new(CookieStore::default()));

        let mut builder = Client::builder()
            .cookie_provider(Arc::clone(&jar))
            .user_agent(&ua)
            .redirect(Policy::limited(10));

        if let Some(p_url) = proxy_url {
            builder = builder.proxy(reqwest::Proxy::all(p_url)?);
        }

        let client = builder.build()?;
        Ok(Self {
            client,
            cookie_jar: jar,
            user_agent: ua,
            signature,
            pacer,
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    pub fn signature(&self) -> ApiSignature {
        self.signature
    }

    pub fn set_signature(&mut self, sig: ApiSignature) {
        self.signature = sig;
    }

    pub fn pacer(&self) -> &TrafficPacer {
        &self.pacer
    }

    /// Populates the cookie jar from portable `CookieRecord` entries.
    pub fn import_cookies(&self, records: &[CookieRecord]) -> ZaloxResult<()> {
        let mut store = self
            .cookie_jar
            .lock()
            .map_err(|_| ZaloxError::Auth("Cookie jar mutex poisoned".into()))?;

        for rec in records {
            let domain = rec.domain.trim_start_matches('.');
            let target_host = if domain.is_empty() {
                "chat.zalo.me"
            } else {
                domain
            };
            let url = Url::parse(&format!("https://{target_host}{}", rec.effective_path()))?;
            let raw_cookie = format!(
                "{}={}; Domain={}; Path={}{}",
                rec.effective_name(),
                rec.value,
                target_host,
                rec.effective_path(),
                if rec.secure { "; Secure" } else { "" }
            );
            let _ = store.parse(&raw_cookie, &url);
        }
        Ok(())
    }

    /// Exports all active cookies from the jar as portable `CookieRecord` items.
    pub fn export_cookies(&self) -> ZaloxResult<Vec<CookieRecord>> {
        let store = self
            .cookie_jar
            .lock()
            .map_err(|_| ZaloxError::Auth("Cookie jar mutex poisoned".into()))?;

        let mut out = Vec::new();
        for c in store.iter_unexpired() {
            out.push(CookieRecord {
                name: c.name().to_owned(),
                key: None,
                value: c.value().to_owned(),
                domain: c
                    .domain()
                    .map(str::to_owned)
                    .unwrap_or_else(|| "zalo.me".into()),
                path: c.path().map(str::to_owned).unwrap_or_else(|| "/".into()),
                secure: c.secure().unwrap_or(true),
                http_only: c.http_only().unwrap_or(false),
            });
        }
        Ok(out)
    }

    /// Builds a cookie header string (`k1=v1; k2=v2`) matching `https://chat.zalo.me` for WebSocket handshakes.
    pub fn cookie_header_for_ws(&self) -> ZaloxResult<String> {
        let store = self
            .cookie_jar
            .lock()
            .map_err(|_| ZaloxError::Auth("Cookie jar mutex poisoned".into()))?;
        let chat_url = Url::parse(ZALO_CHAT_REFERER)?;
        let pairs: Vec<String> = store
            .matches(&chat_url)
            .into_iter()
            .map(|c| format!("{}={}", c.name(), c.value()))
            .collect();
        Ok(pairs.join("; "))
    }

    /// Appends query pairs and optionally injects `zpw_ver` & `zpw_type`.
    pub fn build_endpoint_url(
        &self,
        base_url: &str,
        query: &[(&str, String)],
        include_version: bool,
    ) -> ZaloxResult<Url> {
        let mut url = Url::parse(base_url)?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in query {
                qp.append_pair(k, v);
            }
            if include_version {
                qp.append_pair("zpw_ver", &self.signature.api_version.to_string());
                qp.append_pair("zpw_type", &self.signature.api_type.to_string());
            }
        }
        Ok(url)
    }

    /// Default Zalo Web XHR headers.
    pub fn standard_headers(&self) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/plain, */*"),
        );
        map.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_static("vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7"),
        );
        map.insert(ORIGIN, HeaderValue::from_static(ZALO_CHAT_ORIGIN));
        map.insert(REFERER, HeaderValue::from_static(ZALO_CHAT_REFERER));
        if let Ok(ua) = HeaderValue::from_str(&self.user_agent) {
            map.insert(USER_AGENT, ua);
        }
        map
    }

    /// Probes `https://chat.zalo.me/` static JS bundles to auto-detect live `apiType` & `apiVersion`.
    pub async fn detect_live_signature(&self) -> Option<ApiSignature> {
        let html = self
            .client
            .get(ZALO_CHAT_REFERER)
            .headers(self.standard_headers())
            .send()
            .await
            .ok()?
            .text()
            .await
            .ok()?;

        let is_embed = extract_between(&html, "__ZaBUNDLENAME__", ";")
            .map(|s| s.to_ascii_lowercase().contains("embed"))
            .unwrap_or(false);

        let script_urls = extract_static_bundle_urls(&html);
        {
            let cache = bundle_version_cache().lock().await;
            for u in &script_urls {
                if let Some(sig) = cache.get(u) {
                    return Some(*sig);
                }
            }
        }

        for u in script_urls {
            let Ok(resp) = self
                .client
                .get(&u)
                .headers(self.standard_headers())
                .send()
                .await
            else {
                continue;
            };
            let Ok(js_body) = resp.text().await else {
                continue;
            };
            if let Some(sig) = parse_bundle_signature(&js_body, is_embed) {
                bundle_version_cache().lock().await.insert(u, sig);
                return Some(sig);
            }
        }
        None
    }

    /// Encrypts `params_json` with `cipher`, sends an `application/x-www-form-urlencoded` POST
    /// (`params=<base64>`), and unwraps/decrypts the nested Zalo JSON envelope.
    pub async fn post_encrypted_form<T: DeserializeOwned>(
        &self,
        endpoint: Url,
        cipher: &SessionCipher,
        params_json: &Value,
        paced: bool,
    ) -> ZaloxResult<T> {
        if paced {
            self.pacer.acquire().await;
        }
        let sealed = cipher.seal_params(&serde_json::to_string(params_json)?)?;
        let mut headers = self.standard_headers();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let resp = self
            .client
            .post(endpoint)
            .headers(headers)
            .form(&[("params", sealed)])
            .send()
            .await?;

        self.decode_zalo_envelope(resp, Some(cipher)).await
    }

    /// Encrypts `params_json` into query string `?params=<base64>` and executes `method` (`GET` or `POST`).
    pub async fn request_encrypted_query<T: DeserializeOwned>(
        &self,
        method: Method,
        mut endpoint: Url,
        cipher: &SessionCipher,
        params_json: &Value,
        decrypt_response: bool,
        paced: bool,
    ) -> ZaloxResult<T> {
        if paced {
            self.pacer.acquire().await;
        }
        let sealed = cipher.seal_params(&serde_json::to_string(params_json)?)?;
        endpoint.query_pairs_mut().append_pair("params", &sealed);

        let resp = self
            .client
            .request(method, endpoint)
            .headers(self.standard_headers())
            .send()
            .await?;

        self.decode_zalo_envelope(resp, if decrypt_response { Some(cipher) } else { None })
            .await
    }

    /// Executes a plain GET (no encrypted query body) and decrypts the response envelope.
    pub async fn get_encrypted_response<T: DeserializeOwned>(
        &self,
        endpoint: Url,
        cipher: &SessionCipher,
    ) -> ZaloxResult<T> {
        let resp = self
            .client
            .get(endpoint)
            .headers(self.standard_headers())
            .send()
            .await?;
        self.decode_zalo_envelope(resp, Some(cipher)).await
    }

    /// Unwraps Zalo's outer `{ error_code, error_message, data }` envelope and optional inner AES payload.
    pub async fn decode_zalo_envelope<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
        cipher: Option<&SessionCipher>,
    ) -> ZaloxResult<T> {
        let status = response.status();
        if !status.is_success() {
            return Err(ZaloxError::RemoteApi {
                code: Some(i64::from(status.as_u16())),
                detail: format!("HTTP status {status}"),
            });
        }

        let outer: Value = response.json().await?;
        let outer_code = outer.get("error_code").and_then(Value::as_i64).unwrap_or(0);
        if outer_code != 0 {
            let msg = outer
                .get("error_message")
                .and_then(Value::as_str)
                .unwrap_or("Unknown outer Zalo API error")
                .to_owned();
            return Err(ZaloxError::RemoteApi {
                code: Some(outer_code),
                detail: msg,
            });
        }

        let Some(cipher) = cipher else {
            let data_val = outer.get("data").cloned().unwrap_or(outer);
            return Ok(serde_json::from_value(data_val)?);
        };

        let encrypted_str = outer.get("data").and_then(Value::as_str).ok_or_else(|| {
            ZaloxError::Cipher("Expected encrypted string in outer 'data' field".into())
        })?;

        let decrypted_json = cipher.open_params(encrypted_str)?;
        let inner: Value = serde_json::from_str(&decrypted_json)?;
        let inner_code = inner.get("error_code").and_then(Value::as_i64).unwrap_or(0);
        if inner_code != 0 {
            let msg = inner
                .get("error_message")
                .and_then(Value::as_str)
                .unwrap_or("Unknown inner Zalo API error")
                .to_owned();
            return Err(ZaloxError::RemoteApi {
                code: Some(inner_code),
                detail: msg,
            });
        }

        let payload = inner.get("data").cloned().unwrap_or(Value::Null);
        Ok(serde_json::from_value(payload)?)
    }
}

fn extract_between<'a>(haystack: &'a str, start_marker: &str, end_marker: &str) -> Option<&'a str> {
    let start = haystack.find(start_marker)? + start_marker.len();
    let rest = &haystack[start..];
    let end = rest.find(end_marker)?;
    Some(&rest[..end])
}

fn extract_static_bundle_urls(html: &str) -> Vec<String> {
    let mut prioritized = Vec::new();
    let mut others = Vec::new();
    let base = Url::parse(ZALO_CHAT_REFERER).ok();

    for segment in html.split("<script") {
        let Some(src_pos) = segment.find("src=") else {
            continue;
        };
        let after_src = &segment[src_pos + 4..];
        let quote = after_src.chars().next().unwrap_or(' ');
        if quote != '"' && quote != '\'' {
            continue;
        }
        let rest = &after_src[1..];
        let Some(end_q) = rest.find(quote) else {
            continue;
        };
        let raw_url = &rest[..end_q];
        if !raw_url.ends_with(".js") {
            continue;
        }
        if let Some(ref b) = base {
            if let Ok(resolved) = b.join(raw_url) {
                if resolved
                    .host_str()
                    .unwrap_or_default()
                    .starts_with("zalo-chat-static.")
                {
                    let s = resolved.to_string();
                    if s.contains("/default-embed-render.") {
                        prioritized.push(s);
                    } else {
                        others.push(s);
                    }
                }
            }
        }
    }
    prioritized.extend(others);
    prioritized
}

fn parse_bundle_signature(script: &str, is_embed: bool) -> Option<ApiSignature> {
    let ver_idx = script.find("apiVersion:")? + "apiVersion:".len();
    let ver_digits: String = script[ver_idx..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let api_version: u32 = ver_digits.parse().ok()?;

    let type_idx = script.find("apiType:")? + "apiType:".len();
    let type_tail = &script[type_idx..type_idx.saturating_add(64).min(script.len())];

    let api_type: u32 = if let Some(q_pos) = type_tail.find('?') {
        let branches = &type_tail[q_pos + 1..];
        let mut nums = branches.split(':').map(|part| {
            part.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
        });
        let embed_t: u32 = nums.next()?.parse().ok()?;
        let web_t: u32 = nums.next()?.parse().ok()?;
        if is_embed {
            embed_t
        } else {
            web_t
        }
    } else {
        let digits: String = type_tail
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.parse().ok()?
    };

    if api_type > 0 && api_version > 0 {
        Some(ApiSignature {
            api_type,
            api_version,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minified_bundle_signature_both_ternary_and_literal() {
        let sample =
            r#"var cfg={foo:1,apiVersion:695,apiType:"embed"===__ZaBUNDLENAME__?31:30,bar:2};"#;
        let web_sig = parse_bundle_signature(sample, false).unwrap();
        assert_eq!(web_sig.api_version, 695);
        assert_eq!(web_sig.api_type, 30);

        let embed_sig = parse_bundle_signature(sample, true).unwrap();
        assert_eq!(embed_sig.api_type, 31);
    }
}
