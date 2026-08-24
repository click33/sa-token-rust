// Author: 金书记 | Author: Jin Shuji
//! SSO single sign-on: tickets, sessions, signing, SLO.
//! SSO 单点登录：票据、会话、签名、统一登出。

mod checker;
mod session_store;
mod sign;
mod slo;
mod ticket_store;

pub use checker::{LocalTicketChecker, TicketChecker};
pub use session_store::SsoSessionStore;
pub use sign::{RequestSign, map_sign_err_to_sso};
pub use slo::{NoopSloNotifier, SloNotifier};
pub use ticket_store::SsoTicketStore;

#[cfg(feature = "sso-http")]
pub use checker::HttpTicketChecker;
#[cfg(feature = "sso-http")]
pub use slo::HttpSloNotifier;

use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{SaTokenError, SaTokenResult};
use crate::keys::{LOGIN_TYPE_DEFAULT, LOGIN_TYPE_SSO, LOGIN_TYPE_SSO_CLIENT};
use crate::manager::SaTokenManager;

type LogoutCallback = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// SSO ticket (short-lived, one-time).
/// SSO 票据（短期、一次性）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoTicket {
    /// Unique ticket id (UUID).
    /// 票据唯一 id（UUID）。
    pub ticket_id: String,
    /// Target service URL.
    /// 目标服务 URL。
    pub service: String,
    /// User login id.
    /// 用户登录 id。
    pub login_id: String,
    /// Creation time.
    /// 创建时间。
    pub create_time: DateTime<Utc>,
    /// Expiration time.
    /// 过期时间。
    pub expire_time: DateTime<Utc>,
    /// Used flag (kept for serialization compatibility; consume deletes the key).
    /// 已使用标记（保留以兼容序列化；消费时删除键）。
    pub used: bool,
}

impl SsoTicket {
    /// Create a new ticket.
    /// 创建新票据。
    pub fn new(login_id: String, service: String, timeout_seconds: i64) -> Self {
        let now = Utc::now();
        Self {
            ticket_id: uuid::Uuid::new_v4().to_string(),
            service,
            login_id,
            create_time: now,
            expire_time: now + ChronoDuration::seconds(timeout_seconds),
            used: false,
        }
    }

    /// True when past expire_time.
    /// 已超过过期时间时为 true。
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expire_time
    }

    /// True when unused and not expired.
    /// 未使用且未过期时为 true。
    pub fn is_valid(&self) -> bool {
        !self.used && !self.is_expired()
    }
}

/// Global SSO session tracking client apps.
/// 跟踪各客户端应用的全局 SSO 会话。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    /// User login id.
    /// 用户登录 id。
    pub login_id: String,
    /// Logged-in client URLs.
    /// 已登录的客户端 URL 列表。
    pub clients: Vec<String>,
    /// Creation time.
    /// 创建时间。
    pub create_time: DateTime<Utc>,
    /// Last activity time.
    /// 最后活动时间。
    pub last_active_time: DateTime<Utc>,
}

impl SsoSession {
    /// Create an empty session for login_id.
    /// 为 login_id 创建空会话。
    pub fn new(login_id: String) -> Self {
        let now = Utc::now();
        Self {
            login_id,
            clients: Vec::new(),
            create_time: now,
            last_active_time: now,
        }
    }

    /// Add client if not already listed.
    /// 若尚未在列表中则添加客户端。
    pub fn add_client(&mut self, service: String) {
        if !self.clients.contains(&service) {
            self.clients.push(service);
        }
        self.last_active_time = Utc::now();
    }

    /// Remove a client URL.
    /// 移除客户端 URL。
    pub fn remove_client(&mut self, service: &str) {
        self.clients.retain(|c| c != service);
        self.last_active_time = Utc::now();
    }
}

/// Non-consuming ticket check result.
/// 非消费票据校验结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckTicketResult {
    /// User login id.
    /// 用户登录 id。
    pub login_id: String,
    /// Remaining validity in seconds.
    /// 剩余有效时间（秒）。
    pub remain_seconds: i64,
}

/// SSO server: tickets, sessions, SLO.
/// SSO 服务端：票据、会话、统一登出。
pub struct SsoServer {
    manager: Arc<SaTokenManager>,
    tickets: SsoTicketStore,
    sessions: SsoSessionStore,
    sign: RequestSign,
    slo_notifier: Arc<dyn SloNotifier>,
    ticket_timeout: i64,
    allow_cross_domain: bool,
    allowed_origins: Vec<String>,
}

impl std::fmt::Debug for SsoServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SsoServer { .. }")
    }
}

impl SsoServer {
    /// Create a server from a manager (strict origin defaults).
    /// 从 manager 创建服务端（严格的 Origin 默认值）。
    pub fn new(manager: Arc<SaTokenManager>) -> Self {
        let dao = manager.dao().clone();
        let cfg = SsoConfig::default();
        Self {
            tickets: SsoTicketStore::new(dao.clone(), cfg.ticket_timeout),
            sessions: SsoSessionStore::new(dao.clone()),
            sign: RequestSign::new(cfg.sign_secret.clone(), cfg.sign_window_secs).with_dao(dao),
            slo_notifier: Arc::new(NoopSloNotifier),
            manager,
            ticket_timeout: cfg.ticket_timeout,
            allow_cross_domain: cfg.allow_cross_domain,
            allowed_origins: cfg.allowed_origins,
        }
    }

    /// Apply SSO config (timeout, origins, sign).
    /// 应用 SSO 配置（超时、白名单、签名）。
    pub fn with_config(mut self, config: &SsoConfig) -> Self {
        self.ticket_timeout = config.ticket_timeout;
        self.allow_cross_domain = config.allow_cross_domain;
        self.allowed_origins = config.allowed_origins.clone();
        let dao = self.manager.dao().clone();
        self.tickets = SsoTicketStore::new(dao.clone(), config.ticket_timeout);
        self.sign =
            RequestSign::new(config.sign_secret.clone(), config.sign_window_secs).with_dao(dao);
        self
    }

    /// Override ticket timeout seconds.
    /// 覆盖票据超时秒数。
    pub fn with_ticket_timeout(mut self, timeout: i64) -> Self {
        self.ticket_timeout = timeout;
        let dao = self.manager.dao().clone();
        self.tickets = SsoTicketStore::new(dao, timeout);
        self
    }

    /// Replace the SLO notifier (default [`NoopSloNotifier`]).
    /// 替换 SLO 通知器（默认 [`NoopSloNotifier`]）。
    pub fn with_slo_notifier(mut self, notifier: Arc<dyn SloNotifier>) -> Self {
        self.slo_notifier = notifier;
        self
    }

    /// Shared request signer.
    /// 共享请求签名器。
    pub fn sign(&self) -> &RequestSign {
        &self.sign
    }

    /// Exact-match origin check (requires allow_cross_domain).
    /// 精确匹配 Origin 校验（需开启 allow_cross_domain）。
    pub fn is_allowed_origin(&self, origin: &str) -> bool {
        if !self.allow_cross_domain {
            return false;
        }
        self.allowed_origins
            .iter()
            .any(|allowed| allowed == "*" || allowed == origin)
    }

    fn validate_service_access(&self, service: &str) -> SaTokenResult<()> {
        // allow_cross_domain=false：不做 Origin 白名单（同站默认可发票）
        // allow_cross_domain=true：必须命中 allowed_origins
        if !self.allow_cross_domain {
            return Ok(());
        }
        if self
            .allowed_origins
            .iter()
            .any(|allowed| allowed == "*" || allowed == service)
        {
            return Ok(());
        }
        Err(SaTokenError::ServiceMismatch)
    }

    /// Create and persist a ticket; upsert session client.
    /// 创建并持久化票据；upsert 会话客户端。
    pub async fn create_ticket(
        &self,
        login_id: String,
        service: String,
    ) -> SaTokenResult<SsoTicket> {
        self.validate_service_access(&service)?;
        let ticket = SsoTicket::new(login_id.clone(), service.clone(), self.ticket_timeout);
        self.tickets.save(&ticket).await?;
        self.sessions.upsert_client(&login_id, &service).await?;
        Ok(ticket)
    }

    /// Consume a ticket and return login_id.
    /// 消费票据并返回 login_id。
    pub async fn validate_ticket(&self, ticket_id: &str, service: &str) -> SaTokenResult<String> {
        self.validate_service_access(service)?;
        // 先非消费检查：SLO 登出后会话已删，未用票据也不可兑换
        let (preview, _) = self.tickets.check(ticket_id, service).await?;
        if !self.check_session(&preview).await {
            return Err(SaTokenError::SsoSessionNotFound);
        }
        self.tickets.consume(ticket_id, service).await
    }

    /// Non-consuming ticket check.
    /// 非消费票据校验。
    pub async fn check_ticket(
        &self,
        ticket_id: &str,
        service: &str,
    ) -> SaTokenResult<CheckTicketResult> {
        self.validate_service_access(service)?;
        let (login_id, remain_seconds) = self.tickets.check(ticket_id, service).await?;
        Ok(CheckTicketResult {
            login_id,
            remain_seconds,
        })
    }

    /// Build per-client SLO callback URLs.
    /// 构造各客户端 SLO 回调 URL。
    pub fn build_slo_logout_urls(client_urls: &[String]) -> Vec<String> {
        client_urls
            .iter()
            .map(|client| {
                let base = client.trim_end_matches('/');
                format!(
                    "{}/sso/logout?slo=1&service={}",
                    base,
                    urlencoding::encode(client)
                )
            })
            .collect()
    }

    /// Local logout then notify clients (failures are logged, not rolled back).
    /// 先本地登出再通知客户端（失败仅日志，不回滚）。
    pub async fn logout_with_slo(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        let clients = self.logout(login_id).await?;
        let urls = Self::build_slo_logout_urls(&clients);
        for url in &urls {
            if let Err(e) = self.slo_notifier.notify_logout(url, login_id).await {
                tracing::warn!(url = %url, error = %e, "SLO notify failed");
            }
        }
        Ok(urls)
    }

    /// Login at SSO server and issue a ticket for `service`.
    /// 在 SSO 服务端登录并为 `service` 签发票据。
    pub async fn login(&self, login_id: String, service: String) -> SaTokenResult<SsoTicket> {
        let _token = self
            .manager
            .login_with_options(
                &login_id,
                Some(LOGIN_TYPE_SSO.to_string()),
                None,
                Some(serde_json::json!({
                    "sso_mode": true,
                    "service": service.clone()
                })),
                None,
                None,
            )
            .await?;
        self.create_ticket(login_id, service).await
    }

    /// Remove SSO session and logout related login types.
    /// 删除 SSO 会话并登出相关 login_type。
    pub async fn logout(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        let clients = self.sessions.remove(login_id).await?;
        let _ = self
            .manager
            .logout_by_login_id(LOGIN_TYPE_SSO, login_id)
            .await;
        let _ = self
            .manager
            .logout_by_login_id(LOGIN_TYPE_SSO_CLIENT, login_id)
            .await;
        self.manager
            .logout_by_login_id(LOGIN_TYPE_DEFAULT, login_id)
            .await?;
        Ok(clients)
    }

    /// Load session if present.
    /// 若存在则加载会话。
    pub async fn get_session(&self, login_id: &str) -> Option<SsoSession> {
        self.sessions.get(login_id).await.ok().flatten()
    }

    /// True when a session exists.
    /// 存在会话时为 true。
    pub async fn check_session(&self, login_id: &str) -> bool {
        self.get_session(login_id).await.is_some()
    }

    /// No-op: ticket TTL is enforced by storage.
    /// 空操作：票据 TTL 由存储过期保证。
    pub async fn cleanup_expired_tickets(&self) {}

    /// Active client URLs for login_id.
    /// login_id 的活跃客户端 URL。
    pub async fn get_active_clients(&self, login_id: &str) -> Vec<String> {
        self.get_session(login_id)
            .await
            .map(|s| s.clients)
            .unwrap_or_default()
    }

    /// Session present and SSO login_type still has tokens.
    /// 会话存在且 SSO login_type 仍有 token。
    pub async fn is_logged_in(&self, login_id: &str) -> bool {
        if self.get_session(login_id).await.is_none() {
            return false;
        }
        self.manager
            .get_token_value_list_by_login_id(LOGIN_TYPE_SSO, login_id, None)
            .await
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }
}

/// SSO client application helper.
/// SSO 客户端应用辅助。
pub struct SsoClient {
    manager: Arc<SaTokenManager>,
    server_url: String,
    service_url: String,
    logout_callback: Option<LogoutCallback>,
    checker: Option<Arc<dyn TicketChecker>>,
}

impl std::fmt::Debug for SsoClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SsoClient { .. }")
    }
}

impl SsoClient {
    /// Create a client bound to server and local service URLs.
    /// 创建绑定服务端与本地服务 URL 的客户端。
    pub fn new(manager: Arc<SaTokenManager>, server_url: String, service_url: String) -> Self {
        Self {
            manager,
            server_url,
            service_url,
            logout_callback: None,
            checker: None,
        }
    }

    /// Set logout callback.
    /// 设置登出回调。
    pub fn with_logout_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.logout_callback = Some(Arc::new(callback));
        self
    }

    /// Inject ticket checker (required for [`Self::process_ticket`]).
    /// 注入票据校验器（[`Self::process_ticket`] 必需）。
    pub fn with_ticket_checker(mut self, checker: Arc<dyn TicketChecker>) -> Self {
        self.checker = Some(checker);
        self
    }

    /// SSO server login URL with service callback.
    /// 带服务回调的 SSO 服务端登录 URL。
    pub fn get_login_url(&self) -> String {
        format!(
            "{}?service={}",
            self.server_url,
            urlencoding::encode(&self.service_url)
        )
    }

    /// SSO server logout URL with service callback.
    /// 带服务回调的 SSO 服务端登出 URL。
    pub fn get_logout_url(&self) -> String {
        format!(
            "{}/logout?service={}",
            self.server_url,
            urlencoding::encode(&self.service_url)
        )
    }

    /// Check local SSO-client (or default) login tokens.
    /// 检查本地 SSO 客户端（或默认）登录 token。
    pub async fn check_local_login(&self, login_id: &str) -> bool {
        let sso_ok = self
            .manager
            .get_token_value_list_by_login_id(LOGIN_TYPE_SSO_CLIENT, login_id, None)
            .await
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        if sso_ok {
            return true;
        }
        self.manager
            .get_token_value_list_by_login_id(LOGIN_TYPE_DEFAULT, login_id, None)
            .await
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }

    /// Consume ticket via configured checker (never returns the raw ticket).
    /// 通过已配置校验器消费票据（绝不返回票据原文）。
    pub async fn process_ticket(&self, ticket: &str, service: &str) -> SaTokenResult<String> {
        if service != self.service_url {
            return Err(SaTokenError::ServiceMismatch);
        }
        let checker = self.checker.as_ref().ok_or_else(|| {
            SaTokenError::ConfigError("SSO ticket checker is not configured".into())
        })?;
        checker.check_and_consume(ticket, service).await
    }

    /// Create a local SSO-client login after ticket validation.
    /// 验票后创建本地 SSO 客户端登录。
    pub async fn login_by_ticket(&self, login_id: String) -> SaTokenResult<String> {
        let token = self
            .manager
            .login_with_options(
                &login_id,
                Some(LOGIN_TYPE_SSO_CLIENT.to_string()),
                None,
                Some(serde_json::json!({
                    "sso_client": true,
                    "service_url": self.service_url.clone()
                })),
                None,
                None,
            )
            .await?;
        Ok(token.to_string())
    }

    /// Handle client-side logout.
    /// 处理客户端登出。
    pub async fn handle_logout(&self, login_id: &str) -> SaTokenResult<()> {
        if let Some(callback) = &self.logout_callback {
            callback(login_id);
        }
        let _ = self
            .manager
            .logout_by_login_id(LOGIN_TYPE_SSO_CLIENT, login_id)
            .await;
        self.manager
            .logout_by_login_id(LOGIN_TYPE_DEFAULT, login_id)
            .await?;
        Ok(())
    }

    /// SSO server URL.
    /// SSO 服务端 URL。
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Local service URL.
    /// 本地服务 URL。
    pub fn service_url(&self) -> &str {
        &self.service_url
    }
}

/// SSO configuration.
/// SSO 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfig {
    /// SSO server base URL.
    /// SSO 服务端基础 URL。
    pub server_url: String,
    /// Ticket timeout seconds.
    /// 票据超时秒数。
    pub ticket_timeout: i64,
    /// Whether cross-domain origin checks are enabled.
    /// 是否启用跨域 Origin 校验。
    pub allow_cross_domain: bool,
    /// Allowed origins (exact match; `"*"` only if listed explicitly).
    /// 允许的 Origin（精确匹配；仅列表显式含 `"*"` 时放行全部）。
    pub allowed_origins: Vec<String>,
    /// HMAC secret for HTTP SSO signing (empty disables HTTP checker path).
    /// HTTP SSO 签名 HMAC 密钥（空则禁止走 HTTP checker）。
    pub sign_secret: String,
    /// Timestamp window seconds for signatures.
    /// 签名时间窗（秒）。
    pub sign_window_secs: i64,
}

impl Default for SsoConfig {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:8080/sso".to_string(),
            ticket_timeout: 300,
            allow_cross_domain: false,
            allowed_origins: vec![],
            sign_secret: String::new(),
            sign_window_secs: 300,
        }
    }
}

impl SsoConfig {
    /// Start a builder.
    /// 启动构建器。
    pub fn builder() -> SsoConfigBuilder {
        SsoConfigBuilder::default()
    }
}

/// Builder for [`SsoConfig`].
/// [`SsoConfig`] 构建器。
#[derive(Default)]
pub struct SsoConfigBuilder {
    config: SsoConfig,
}

impl std::fmt::Debug for SsoConfigBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SsoConfigBuilder { .. }")
    }
}

impl SsoConfigBuilder {
    /// Set server URL.
    /// 设置服务端 URL。
    pub fn server_url(mut self, url: impl Into<String>) -> Self {
        self.config.server_url = url.into();
        self
    }

    /// Set ticket timeout seconds.
    /// 设置票据超时秒数。
    pub fn ticket_timeout(mut self, timeout: i64) -> Self {
        self.config.ticket_timeout = timeout;
        self
    }

    /// Enable or disable cross-domain checks.
    /// 启用或禁用跨域校验。
    pub fn allow_cross_domain(mut self, allow: bool) -> Self {
        self.config.allow_cross_domain = allow;
        self
    }

    /// Replace allowed origins list.
    /// 替换允许的 Origin 列表。
    pub fn allowed_origins(mut self, origins: Vec<String>) -> Self {
        self.config.allowed_origins = origins;
        self
    }

    /// Append one allowed origin.
    /// 追加一个允许的 Origin。
    pub fn add_allowed_origin(mut self, origin: String) -> Self {
        self.config.allowed_origins.push(origin);
        self
    }

    /// Set sign secret.
    /// 设置签名密钥。
    pub fn sign_secret(mut self, secret: impl Into<String>) -> Self {
        self.config.sign_secret = secret.into();
        self
    }

    /// Set sign window seconds.
    /// 设置签名时间窗秒数。
    pub fn sign_window_secs(mut self, secs: i64) -> Self {
        self.config.sign_window_secs = secs;
        self
    }

    /// Finish building.
    /// 完成构建。
    pub fn build(self) -> SsoConfig {
        self.config
    }
}

/// Aggregates optional server + client with shared config.
/// 聚合可选服务端 + 客户端与共享配置。
pub struct SsoManager {
    server: Option<Arc<SsoServer>>,
    client: Option<Arc<SsoClient>>,
    config: SsoConfig,
}

impl std::fmt::Debug for SsoManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SsoManager { .. }")
    }
}

impl SsoManager {
    /// Create with config only.
    /// 仅用配置创建。
    pub fn new(config: SsoConfig) -> Self {
        Self {
            server: None,
            client: None,
            config,
        }
    }

    /// Attach server.
    /// 挂载服务端。
    pub fn with_server(mut self, server: Arc<SsoServer>) -> Self {
        self.server = Some(server);
        self
    }

    /// Attach client.
    /// 挂载客户端。
    pub fn with_client(mut self, client: Arc<SsoClient>) -> Self {
        self.client = Some(client);
        self
    }

    /// Server reference.
    /// 服务端引用。
    pub fn server(&self) -> Option<&Arc<SsoServer>> {
        self.server.as_ref()
    }

    /// Client reference.
    /// 客户端引用。
    pub fn client(&self) -> Option<&Arc<SsoClient>> {
        self.client.as_ref()
    }

    /// Config reference.
    /// 配置引用。
    pub fn config(&self) -> &SsoConfig {
        &self.config
    }

    /// Exact-match origin check using config.
    /// 使用配置做精确 Origin 校验。
    pub fn is_allowed_origin(&self, origin: &str) -> bool {
        if !self.config.allow_cross_domain {
            return false;
        }
        self.config
            .allowed_origins
            .iter()
            .any(|allowed| allowed == "*" || allowed == origin)
    }
}
