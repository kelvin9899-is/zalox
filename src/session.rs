//! Client builder and authenticated `ZaloxSession` handle.

use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use tokio::sync::{oneshot, Mutex};

use crate::{
    auth::{execute_qr_login, AuthCredentials, QrAuthEvent},
    bot::BotRouter,
    cipher::{compute_request_mac, generate_device_imei, HandshakeTicket, SessionCipher},
    error::{ZaloxError, ZaloxResult},
    realtime::{EventStreamConfig, RealtimeHandle},
    services::{ContactsService, GroupsService, MediaService, MessagingService},
    transport::{http::DEFAULT_USER_AGENT, ApiSignature, HttpGateway, PacingPolicy, TrafficPacer},
    types::{
        ExtraVersions, LoginBootstrapData, RuntimeSettings, ServerInfoEnvelope, ServiceDirectory,
        UploadedMediaNotice,
    },
};

const LOGIN_INFO_ENDPOINT: &str = "https://wpa.chat.zalo.me/api/login/getLoginInfo";
const SERVER_INFO_ENDPOINT: &str = "https://wpa.chat.zalo.me/api/login/getServerInfo";

/// Fluent builder for configuring a `ZaloxClient`.
#[derive(Debug, Clone)]
pub struct ZaloxBuilder {
    user_agent: String,
    language: String,
    explicit_signature: Option<ApiSignature>,
    auto_detect_version: bool,
    pacing: PacingPolicy,
    self_events: bool,
    proxy_url: Option<String>,
}

impl Default for ZaloxBuilder {
    fn default() -> Self {
        Self {
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            language: "vi".to_owned(),
            explicit_signature: None,
            auto_detect_version: true,
            pacing: PacingPolicy::balanced(),
            self_events: false,
            proxy_url: None,
        }
    }
}

impl ZaloxBuilder {
    /// Overrides the browser User-Agent string sent on HTTP and WebSocket connections.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    /// Sets the preferred client language (`"vi"` or `"en"`).
    pub fn language(mut self, lang: impl Into<String>) -> Self {
        self.language = lang.into();
        self
    }

    /// Pins a specific `(api_type, api_version)` instead of probing `chat.zalo.me`.
    pub fn api_signature(mut self, api_type: u32, api_version: u32) -> Self {
        self.explicit_signature = Some(ApiSignature {
            api_type,
            api_version,
        });
        self.auto_detect_version = false;
        self
    }

    /// Configures outbound request pacing & randomized anti-ban jitter.
    pub fn pacing(mut self, policy: PacingPolicy) -> Self {
        self.pacing = policy;
        self
    }

    /// Controls whether messages/reactions authored by the logged-in account itself are emitted.
    pub fn self_events(mut self, enabled: bool) -> Self {
        self.self_events = enabled;
        self
    }

    /// Routes all HTTP requests through an HTTP/SOCKS5 proxy URL.
    pub fn proxy(mut self, proxy_url: impl Into<String>) -> Self {
        self.proxy_url = Some(proxy_url.into());
        self
    }

    /// Finalizes configuration and returns a `ZaloxClient`.
    pub fn build(self) -> ZaloxClient {
        ZaloxClient { cfg: self }
    }
}

/// Entry-point factory for authenticating Zalo personal accounts via QR or saved credentials.
#[derive(Debug, Clone)]
pub struct ZaloxClient {
    cfg: ZaloxBuilder,
}

impl Default for ZaloxClient {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl ZaloxClient {
    /// Starts configuring a new `ZaloxClient`.
    pub fn builder() -> ZaloxBuilder {
        ZaloxBuilder::default()
    }

    /// Authenticates interactively via QR code, invoking `on_event` whenever a QR is generated or scanned.
    pub async fn login_with_qr<F>(&self, on_event: F) -> ZaloxResult<ZaloxSession>
    where
        F: FnMut(QrAuthEvent),
    {
        let pacer = Arc::new(TrafficPacer::new(self.cfg.pacing));
        let sig = self.cfg.explicit_signature.unwrap_or_default();
        let gateway = HttpGateway::new(
            &self.cfg.user_agent,
            sig,
            pacer,
            self.cfg.proxy_url.as_deref(),
        )?;

        let outcome = execute_qr_login(&gateway, on_event).await?;
        let imei = generate_device_imei(&self.cfg.user_agent);
        let creds = AuthCredentials {
            imei,
            cookies: crate::auth::CookieInput::List(outcome.cookies),
            user_agent: self.cfg.user_agent.clone(),
            language: self.cfg.language.clone(),
        };

        self.bootstrap_session(gateway, creds).await
    }

    /// Resumes an existing session from an `AuthCredentials` bundle.
    pub async fn login_with_credentials(
        &self,
        creds: AuthCredentials,
    ) -> ZaloxResult<ZaloxSession> {
        creds.validate()?;
        let pacer = Arc::new(TrafficPacer::new(self.cfg.pacing));
        let sig = self.cfg.explicit_signature.unwrap_or_default();
        let gateway =
            HttpGateway::new(&creds.user_agent, sig, pacer, self.cfg.proxy_url.as_deref())?;
        gateway.import_cookies(creds.cookies.as_slice())?;
        self.bootstrap_session(gateway, creds).await
    }

    /// Decrypts a `ZLX1` vault file and resumes the session in one step.
    pub async fn login_with_vault(
        &self,
        vault_path: impl AsRef<Path>,
        passphrase: &str,
    ) -> ZaloxResult<ZaloxSession> {
        let creds = AuthCredentials::load_encrypted(vault_path, passphrase).await?;
        self.login_with_credentials(creds).await
    }

    async fn bootstrap_session(
        &self,
        mut gateway: HttpGateway,
        creds: AuthCredentials,
    ) -> ZaloxResult<ZaloxSession> {
        if self.cfg.auto_detect_version && self.cfg.explicit_signature.is_none() {
            if let Some(live_sig) = gateway.detect_live_signature().await {
                gateway.set_signature(live_sig);
            }
        }

        let login_info = fetch_encrypted_login_info(&gateway, &creds).await?;
        let server_info = fetch_server_info(&gateway, &creds).await?;

        if login_info.zpw_enk.is_empty() || login_info.uid.is_empty() {
            return Err(ZaloxError::Auth(
                "getLoginInfo succeeded without returning uid / zpw_enk".into(),
            ));
        }

        let cipher = SessionCipher::from_base64_secret(&login_info.zpw_enk)?;
        let inner = SessionCore {
            uid: login_info.uid.clone(),
            imei: creds.imei,
            language: creds.language,
            self_events: self.cfg.self_events,
            gateway,
            cipher,
            services: login_info.zpw_service_map_v3,
            ws_endpoints: login_info.zpw_ws,
            settings: server_info.settings,
            extra_ver: server_info.extra_ver,
            pending_uploads: Mutex::new(HashMap::new()),
        };

        Ok(ZaloxSession {
            core: Arc::new(inner),
        })
    }
}

pub(crate) struct SessionCore {
    pub uid: String,
    pub imei: String,
    pub language: String,
    pub self_events: bool,
    pub gateway: HttpGateway,
    pub cipher: SessionCipher,
    pub services: ServiceDirectory,
    pub ws_endpoints: Vec<String>,
    pub settings: RuntimeSettings,
    pub extra_ver: ExtraVersions,
    pub pending_uploads: Mutex<HashMap<String, oneshot::Sender<UploadedMediaNotice>>>,
}

/// Thread-safe, cheaply cloneable authenticated Zalo session (`Arc`-backed).
#[derive(Clone)]
pub struct ZaloxSession {
    pub(crate) core: Arc<SessionCore>,
}

impl std::fmt::Debug for ZaloxSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZaloxSession")
            .field("uid", &self.core.uid)
            .field("signature", &self.core.gateway.signature())
            .finish()
    }
}

impl ZaloxSession {
    /// Returns the authenticated account's Zalo User ID (`uid`).
    pub fn uid(&self) -> &str {
        &self.core.uid
    }

    /// Returns the device IMEI bound to this session.
    pub fn imei(&self) -> &str {
        &self.core.imei
    }

    /// Exports portable `AuthCredentials` so the session can be persisted and restored later.
    pub fn export_credentials(&self) -> ZaloxResult<AuthCredentials> {
        let cookies = self.core.gateway.export_cookies()?;
        Ok(AuthCredentials {
            imei: self.core.imei.clone(),
            cookies: crate::auth::CookieInput::List(cookies),
            user_agent: self.core.gateway.user_agent().to_owned(),
            language: self.core.language.clone(),
        })
    }

    /// Exports and encrypts the current session into a password-protected `ZLX1` vault file.
    pub async fn save_vault(&self, path: impl AsRef<Path>, passphrase: &str) -> ZaloxResult<()> {
        let creds = self.export_credentials()?;
        creds.save_encrypted(path, passphrase).await
    }

    /// Domain handle for sending, quoting, styling, recalling, forwarding, and reacting to messages.
    pub fn messaging(&self) -> MessagingService {
        MessagingService::new(self.clone())
    }

    /// Domain handle for contact discovery, user profiles, friend requests, aliases, and blocking.
    pub fn contacts(&self) -> ContactsService {
        ContactsService::new(self.clone())
    }

    /// Domain handle for group management, membership administration, invite links, and polls.
    pub fn groups(&self) -> GroupsService {
        GroupsService::new(self.clone())
    }

    /// Domain handle for pure-Rust image header probing and chunked media/file uploads.
    pub fn media(&self) -> MediaService {
        MediaService::new(self.clone())
    }

    /// Starts the real-time WebSocket event stream with default reconnect settings.
    pub fn subscribe_events(&self) -> ZaloxResult<RealtimeHandle> {
        RealtimeHandle::connect(self.clone(), EventStreamConfig::default())
    }

    /// Starts the real-time WebSocket event stream with custom reconnect settings.
    pub fn subscribe_events_with(&self, cfg: EventStreamConfig) -> ZaloxResult<RealtimeHandle> {
        RealtimeHandle::connect(self.clone(), cfg)
    }

    /// Runs a declarative `BotRouter` loop until the event stream closes or a shutdown signal fires.
    pub async fn run_bot<S>(&self, router: BotRouter<S>) -> ZaloxResult<()>
    where
        S: Send + Sync + 'static,
    {
        router.serve(self.clone()).await
    }

    pub(crate) async fn register_upload_waiter(
        &self,
        file_id: String,
    ) -> oneshot::Receiver<UploadedMediaNotice> {
        let (tx, rx) = oneshot::channel();
        self.core.pending_uploads.lock().await.insert(file_id, tx);
        rx
    }

    pub(crate) async fn fulfill_upload_waiter(&self, notice: UploadedMediaNotice) {
        if let Some(tx) = self
            .core
            .pending_uploads
            .lock()
            .await
            .remove(&notice.file_id)
        {
            let _ = tx.send(notice);
        }
    }
}

pub(crate) fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn fetch_encrypted_login_info(
    gateway: &HttpGateway,
    creds: &AuthCredentials,
) -> ZaloxResult<LoginBootstrapData> {
    let sig = gateway.signature();
    let now_ms = now_epoch_ms();
    let ticket = HandshakeTicket::generate(sig.api_type, &creds.imei, now_ms)?;

    let inner_body = serde_json::json!({
        "computer_name": "Web",
        "imei": creds.imei,
        "language": creds.language,
        "ts": now_ms,
    });
    let sealed_params = ticket.seal_json(&inner_body.to_string())?;

    let mut mac_map = BTreeMap::new();
    mac_map.insert("zcid".into(), ticket.zcid.clone());
    mac_map.insert("zcid_ext".into(), ticket.zcid_ext.clone());
    mac_map.insert("enc_ver".into(), ticket.enc_ver.to_owned());
    mac_map.insert("params".into(), sealed_params.clone());
    mac_map.insert("type".into(), sig.api_type.to_string());
    mac_map.insert("client_version".into(), sig.api_version.to_string());
    let signkey = compute_request_mac("getlogininfo", &mac_map);

    let mut query_vec: Vec<(&str, String)> = vec![
        ("zcid", ticket.zcid.clone()),
        ("zcid_ext", ticket.zcid_ext.clone()),
        ("enc_ver", ticket.enc_ver.to_owned()),
        ("params", sealed_params),
        ("type", sig.api_type.to_string()),
        ("client_version", sig.api_version.to_string()),
        ("signkey", signkey),
        ("nretry", "0".into()),
    ];
    let url = gateway.build_endpoint_url(LOGIN_INFO_ENDPOINT, &query_vec, true)?;
    query_vec.clear();

    let outer: Value = gateway
        .client()
        .get(url)
        .headers(gateway.standard_headers())
        .send()
        .await?
        .json()
        .await?;

    let err_code = outer.get("error_code").and_then(Value::as_i64).unwrap_or(0);
    if err_code != 0 {
        let detail = outer
            .get("error_message")
            .and_then(Value::as_str)
            .unwrap_or("getLoginInfo failed")
            .to_owned();
        return Err(ZaloxError::Auth(format!("({err_code}) {detail}")));
    }

    let encrypted_data = outer
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| ZaloxError::Auth("getLoginInfo response missing encrypted 'data'".into()))?;

    let plain_json = ticket.open_response(encrypted_data)?;
    let decoded_env: Value = serde_json::from_str(&plain_json)?;
    let inner_data = decoded_env
        .get("data")
        .cloned()
        .ok_or_else(|| ZaloxError::Auth("Decrypted getLoginInfo missing inner 'data'".into()))?;

    Ok(serde_json::from_value(inner_data)?)
}

async fn fetch_server_info(
    gateway: &HttpGateway,
    creds: &AuthCredentials,
) -> ZaloxResult<ServerInfoEnvelope> {
    let sig = gateway.signature();
    let mut mac_map = BTreeMap::new();
    mac_map.insert("imei".into(), creds.imei.clone());
    mac_map.insert("type".into(), sig.api_type.to_string());
    mac_map.insert("client_version".into(), sig.api_version.to_string());
    mac_map.insert("computer_name".into(), "Web".into());
    let signkey = compute_request_mac("getserverinfo", &mac_map);

    let url = gateway.build_endpoint_url(
        SERVER_INFO_ENDPOINT,
        &[
            ("imei", creds.imei.clone()),
            ("type", sig.api_type.to_string()),
            ("client_version", sig.api_version.to_string()),
            ("computer_name", "Web".into()),
            ("signkey", signkey),
        ],
        false,
    )?;

    let outer: Value = gateway
        .client()
        .get(url)
        .headers(gateway.standard_headers())
        .send()
        .await?
        .json()
        .await?;

    let data = outer
        .get("data")
        .cloned()
        .ok_or_else(|| ZaloxError::Auth("getServerInfo returned null 'data'".into()))?;
    Ok(serde_json::from_value(data)?)
}
