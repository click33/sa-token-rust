// Author: 金书记 | Author: Jin Shuji
//! OAuth2 authorization-code / refresh / password / client-credentials.
//! OAuth2 授权码 / 刷新 / 密码 / 客户端凭证。

mod password;
mod pkce;
mod secret;

pub use password::PasswordVerifier;
pub use pkce::{CodeChallengeMethod, PkceChallenge};
pub use secret::ClientSecretHasher;

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::SaTokenConfig;
use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use crate::manager::SaTokenManager;

/// OAuth2 client registration record.
/// OAuth2 客户端注册记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Client {
    /// Client identifier.
    /// 客户端标识。
    pub client_id: String,
    /// Stored Argon2 PHC string. Never log this value.
    /// 存储的 Argon2 PHC 串。禁止写入日志。
    #[serde(default, alias = "client_secret")]
    pub client_secret_hash: String,
    /// Transient plaintext used only at registration; never serialized.
    /// 仅注册时使用的明文，永不序列化。
    #[serde(default, skip_serializing, skip_deserializing)]
    pub client_secret: String,
    /// Allowed redirect URIs (exact match).
    /// 允许的重定向 URI（精确匹配）。
    pub redirect_uris: Vec<String>,
    /// Supported grant types.
    /// 支持的授权类型。
    pub grant_types: Vec<String>,
    /// Allowed scopes.
    /// 允许的权限范围。
    pub scope: Vec<String>,
    /// Public client: no secret; PKCE required.
    /// 公共客户端：无密钥；必须 PKCE。
    #[serde(default)]
    pub public_client: bool,
}

/// Authorization code payload stored until exchange / consume.
/// 兑换/消费前存储的授权码载荷。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// Opaque authorization code value.
    /// 不透明授权码值。
    pub code: String,
    /// Issuing client id.
    /// 签发方客户端 id。
    pub client_id: String,
    /// Resource owner id.
    /// 资源所有者 id。
    pub user_id: String,
    /// Bound redirect URI.
    /// 绑定的重定向 URI。
    pub redirect_uri: String,
    /// Granted scopes.
    /// 已授予的权限范围。
    pub scope: Vec<String>,
    /// Creation time.
    /// 创建时间。
    pub created_at: DateTime<Utc>,
    /// Expiration time.
    /// 过期时间。
    pub expires_at: DateTime<Utc>,
    /// Optional PKCE challenge.
    /// 可选 PKCE 挑战。
    pub pkce: Option<PkceChallenge>,
    /// Optional OAuth `state`.
    /// 可选 OAuth `state`。
    pub state: Option<String>,
}

/// Access token response returned to the client.
/// 返回给客户端的访问令牌响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// Access token value.
    /// 访问令牌值。
    pub access_token: String,
    /// Token type (usually Bearer).
    /// 令牌类型（通常为 Bearer）。
    pub token_type: String,
    /// Lifetime in seconds.
    /// 有效期（秒）。
    pub expires_in: i64,
    /// Optional refresh token.
    /// 可选刷新令牌。
    pub refresh_token: Option<String>,
    /// Granted scopes.
    /// 已授予的权限范围。
    pub scope: Vec<String>,
}

/// Persisted access-token metadata.
/// 持久化的访问令牌元数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2TokenInfo {
    /// Access token value.
    /// 访问令牌值。
    pub access_token: String,
    /// Client id.
    /// 客户端 id。
    pub client_id: String,
    /// Resource owner id.
    /// 资源所有者 id。
    pub user_id: String,
    /// Granted scopes.
    /// 已授予的权限范围。
    pub scope: Vec<String>,
    /// Creation time.
    /// 创建时间。
    pub created_at: DateTime<Utc>,
    /// Expiration time.
    /// 过期时间。
    pub expires_at: DateTime<Utc>,
    /// Linked refresh token if any.
    /// 关联的刷新令牌（如有）。
    pub refresh_token: Option<String>,
}

/// Refresh-token record used for atomic rotation.
/// 用于原子轮换的刷新令牌记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2RefreshRecord {
    /// Resource owner id.
    /// 资源所有者 id。
    pub user_id: String,
    /// Client id.
    /// 客户端 id。
    pub client_id: String,
    /// Granted scopes.
    /// 已授予的权限范围。
    pub scope: Vec<String>,
    /// Current access token to revoke on refresh.
    /// 刷新时待撤销的当前访问令牌。
    pub access_token: String,
    /// Creation time.
    /// 创建时间。
    pub created_at: DateTime<Utc>,
}

/// Unified token-endpoint request.
/// 统一的 token 端点请求。
#[derive(Debug, Default)]
pub struct TokenIssueRequest {
    /// Grant type name.
    /// 授权类型名称。
    pub grant_type: String,
    /// Client id.
    /// 客户端 id。
    pub client_id: String,
    /// Client secret (empty for public clients).
    /// 客户端密钥（公共客户端可为空）。
    pub client_secret: String,
    /// Authorization code (authorization_code grant).
    /// 授权码（authorization_code 模式）。
    pub code: Option<String>,
    /// Redirect URI (authorization_code grant).
    /// 重定向 URI（authorization_code 模式）。
    pub redirect_uri: Option<String>,
    /// Refresh token (refresh_token grant).
    /// 刷新令牌（refresh_token 模式）。
    pub refresh_token: Option<String>,
    /// Username (password grant).
    /// 用户名（password 模式）。
    pub username: Option<String>,
    /// Password (password grant).
    /// 密码（password 模式）。
    pub password: Option<String>,
    /// Requested scopes.
    /// 请求的权限范围。
    pub scope: Vec<String>,
    /// PKCE code_verifier.
    /// PKCE code_verifier。
    pub code_verifier: Option<String>,
}

/// OAuth2 protocol manager backed by [`SaTokenDao`].
/// 基于 [`SaTokenDao`] 的 OAuth2 协议管理器。
pub struct OAuth2Manager {
    dao: Arc<SaTokenDao>,
    code_ttl: i64,
    token_ttl: i64,
    refresh_token_ttl: i64,
    require_pkce: bool,
    allow_legacy_plain_secret: bool,
    password_verifier: Option<Arc<dyn PasswordVerifier>>,
}

impl std::fmt::Debug for OAuth2Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OAuth2Manager { .. }")
    }
}

impl OAuth2Manager {
    /// Build from raw storage with default config / key prefix.
    /// 从原始存储构建（默认配置与键前缀）。
    pub fn new(storage: Arc<dyn sa_token_adapter::storage::SaStorage>) -> Self {
        let dao = Arc::new(SaTokenDao::new(storage, Arc::new(SaTokenConfig::default())));
        Self::from_dao(dao)
    }

    /// Build from an existing Dao (preferred when sharing Manager keys).
    /// 从已有 Dao 构建（与 Manager 共享键时推荐）。
    pub fn from_dao(dao: Arc<SaTokenDao>) -> Self {
        Self {
            dao,
            code_ttl: 600,
            token_ttl: 3600,
            refresh_token_ttl: 2592000,
            require_pkce: false,
            allow_legacy_plain_secret: false,
            password_verifier: None,
        }
    }

    /// Align Dao / key prefix with an existing manager.
    /// 与已有 manager 对齐 Dao / 键前缀。
    pub fn from_manager(manager: &SaTokenManager) -> Self {
        Self::from_dao(manager.dao().clone())
    }

    /// Override code / access / refresh TTLs (seconds).
    /// 覆盖授权码 / 访问令牌 / 刷新令牌 TTL（秒）。
    pub fn with_ttl(mut self, code_ttl: i64, token_ttl: i64, refresh_token_ttl: i64) -> Self {
        self.code_ttl = code_ttl;
        self.token_ttl = token_ttl;
        self.refresh_token_ttl = refresh_token_ttl;
        self
    }

    /// Require PKCE for confidential clients as well.
    /// 机密客户端也强制要求 PKCE。
    pub fn with_require_pkce(mut self, require: bool) -> Self {
        self.require_pkce = require;
        self
    }

    /// Allow verifying legacy plaintext secrets stored under the hash field.
    /// 允许校验哈希字段中残留的历史明文密钥。
    pub fn with_allow_legacy_plain_secret(mut self, allow: bool) -> Self {
        self.allow_legacy_plain_secret = allow;
        self
    }

    /// Inject password grant verifier (required for password grant).
    /// 注入密码模式校验器（password grant 必需）。
    pub fn with_password_verifier(mut self, verifier: Arc<dyn PasswordVerifier>) -> Self {
        self.password_verifier = Some(verifier);
        self
    }

    /// Register a client after hashing `plain_secret` (unless public).
    /// 注册客户端：对 `plain_secret` 哈希后落库（公共客户端除外）。
    pub async fn register_client_with_secret(
        &self,
        mut client: OAuth2Client,
        plain_secret: &str,
    ) -> SaTokenResult<()> {
        if client.public_client {
            client.client_secret_hash.clear();
        } else {
            client.client_secret_hash = ClientSecretHasher::hash_plain_secret(plain_secret)?;
        }
        client.client_secret.clear();
        let key = self.dao.keys().oauth2_client(&client.client_id);
        self.dao.set_object(&key, &client, None).await
    }

    /// Compatibility wrapper: hashes `client.client_secret` when hash is empty.
    /// 兼容包装：hash 为空时哈希 `client.client_secret`。
    pub async fn register_client(&self, client: &OAuth2Client) -> SaTokenResult<()> {
        self.register_client_with_secret(client.clone(), &client.client_secret)
            .await
    }

    /// Load a registered client by id.
    /// 按 id 加载已注册客户端。
    pub async fn get_client(&self, client_id: &str) -> SaTokenResult<OAuth2Client> {
        let key = self.dao.keys().oauth2_client(client_id);
        self.dao
            .get_object(&key)
            .await?
            .ok_or(SaTokenError::OAuth2ClientNotFound)
    }

    /// Verify client credentials (public clients always succeed).
    /// 校验客户端凭据（公共客户端恒成功）。
    pub async fn verify_client(&self, client_id: &str, client_secret: &str) -> SaTokenResult<bool> {
        let client = self.get_client(client_id).await?;
        if client.public_client {
            return Ok(true);
        }
        if ClientSecretHasher::is_hashed(&client.client_secret_hash) {
            return ClientSecretHasher::verify_plain_secret(
                client_secret,
                &client.client_secret_hash,
            );
        }
        if self.allow_legacy_plain_secret {
            return Ok(crate::http_basic::ct_eq(
                client_secret.as_bytes(),
                client.client_secret_hash.as_bytes(),
            ));
        }
        Ok(false)
    }

    /// Build an authorization code (does not persist).
    /// 构造授权码（不落库）。
    pub fn generate_authorization_code(
        &self,
        client_id: String,
        user_id: String,
        redirect_uri: String,
        scope: Vec<String>,
        pkce: Option<PkceChallenge>,
        state: Option<String>,
    ) -> AuthorizationCode {
        let now = Utc::now();
        AuthorizationCode {
            code: format!("code_{}", Uuid::new_v4().simple()),
            client_id,
            user_id,
            redirect_uri,
            scope,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(self.code_ttl),
            pkce,
            state,
        }
    }

    /// Persist an authorization code with TTL.
    /// 以 TTL 持久化授权码。
    pub async fn store_authorization_code(
        &self,
        auth_code: &AuthorizationCode,
    ) -> SaTokenResult<()> {
        let key = self.dao.keys().oauth2_code(&auth_code.code);
        let ttl = Some(Duration::from_secs(self.code_ttl as u64));
        self.dao.set_object(&key, auth_code, ttl).await
    }

    /// Atomically consume an authorization code (`take_string`).
    /// 原子消费授权码（`take_string`）。
    pub async fn consume_authorization_code(&self, code: &str) -> SaTokenResult<AuthorizationCode> {
        let key = self.dao.keys().oauth2_code(code);
        let raw = self
            .dao
            .take_string(&key)
            .await?
            .ok_or(SaTokenError::OAuth2CodeNotFound)?;
        let auth_code: AuthorizationCode = self.dao.decode(&raw)?;
        if Utc::now() > auth_code.expires_at {
            return Err(SaTokenError::TokenExpired);
        }
        Ok(auth_code)
    }

    /// Exchange authorization code for tokens (with optional PKCE).
    /// 用授权码兑换令牌（可选 PKCE）。
    pub async fn exchange_code_for_token(
        &self,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> SaTokenResult<AccessToken> {
        let client = self.get_client(client_id).await?;
        if !client.public_client && !self.verify_client(client_id, client_secret).await? {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }
        let auth_code = self.consume_authorization_code(code).await?;
        if auth_code.client_id != client_id {
            return Err(SaTokenError::OAuth2ClientIdMismatch);
        }
        if auth_code.redirect_uri != redirect_uri {
            return Err(SaTokenError::OAuth2RedirectUriMismatch);
        }
        let need_pkce = client.public_client || self.require_pkce || auth_code.pkce.is_some();
        if client.public_client {
            let pkce = auth_code
                .pkce
                .as_ref()
                .ok_or(SaTokenError::OAuth2PkceRequiredForPublicClient)?;
            if !matches!(pkce.code_challenge_method, CodeChallengeMethod::S256) {
                return Err(SaTokenError::OAuth2PkceRequiredForPublicClient);
            }
            let verifier = code_verifier.ok_or(SaTokenError::OAuth2PkceRequired)?;
            pkce.verify(verifier)?;
        } else if need_pkce {
            let pkce = auth_code
                .pkce
                .as_ref()
                .ok_or(SaTokenError::OAuth2PkceRequired)?;
            let verifier = code_verifier.ok_or(SaTokenError::OAuth2PkceRequired)?;
            pkce.verify(verifier)?;
        }
        self.generate_access_token(&auth_code.client_id, &auth_code.user_id, auth_code.scope)
            .await
    }

    /// Issue and persist an access + refresh token pair.
    /// 签发并持久化访问令牌 + 刷新令牌对。
    pub async fn generate_access_token(
        &self,
        client_id: &str,
        user_id: &str,
        scope: Vec<String>,
    ) -> SaTokenResult<AccessToken> {
        let now = Utc::now();
        let access_token = format!("at_{}", Uuid::new_v4().simple());
        let refresh_token = format!("rt_{}", Uuid::new_v4().simple());
        let token_info = OAuth2TokenInfo {
            access_token: access_token.clone(),
            client_id: client_id.to_string(),
            user_id: user_id.to_string(),
            scope: scope.clone(),
            created_at: now,
            expires_at: now + chrono::Duration::seconds(self.token_ttl),
            refresh_token: Some(refresh_token.clone()),
        };
        let at_key = self.dao.keys().oauth2_token(&access_token);
        self.dao
            .set_object(
                &at_key,
                &token_info,
                Some(Duration::from_secs(self.token_ttl as u64)),
            )
            .await?;
        let record = OAuth2RefreshRecord {
            user_id: user_id.to_string(),
            client_id: client_id.to_string(),
            scope: scope.clone(),
            access_token: access_token.clone(),
            created_at: now,
        };
        let rt_key = self.dao.keys().oauth2_refresh(&refresh_token);
        self.dao
            .set_object(
                &rt_key,
                &record,
                Some(Duration::from_secs(self.refresh_token_ttl as u64)),
            )
            .await?;
        Ok(AccessToken {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.token_ttl,
            refresh_token: Some(refresh_token),
            scope,
        })
    }

    /// Load and validate an access token.
    /// 加载并校验访问令牌。
    pub async fn verify_access_token(&self, access_token: &str) -> SaTokenResult<OAuth2TokenInfo> {
        let key = self.dao.keys().oauth2_token(access_token);
        let info: OAuth2TokenInfo = self
            .dao
            .get_object(&key)
            .await?
            .ok_or(SaTokenError::OAuth2AccessTokenNotFound)?;
        if Utc::now() > info.expires_at {
            let _ = self.dao.delete(&key).await;
            return Err(SaTokenError::TokenExpired);
        }
        Ok(info)
    }

    /// Rotate refresh token atomically (`take_string` + rewrite on failure).
    /// 原子轮换刷新令牌（`take_string`；失败时回写）。
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: &str,
    ) -> SaTokenResult<AccessToken> {
        if !self.verify_client(client_id, client_secret).await? {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }
        let rt_key = self.dao.keys().oauth2_refresh(refresh_token);
        let raw = self
            .dao
            .take_string(&rt_key)
            .await?
            .ok_or(SaTokenError::OAuth2RefreshTokenNotFound)?;
        let record: OAuth2RefreshRecord = self.dao.decode(&raw)?;
        if record.client_id != client_id {
            let ttl = Some(Duration::from_secs(self.refresh_token_ttl as u64));
            let _ = self.dao.set_string(&rt_key, &raw, ttl).await;
            return Err(SaTokenError::OAuth2ClientIdMismatch);
        }
        match self
            .generate_access_token(&record.client_id, &record.user_id, record.scope.clone())
            .await
        {
            Ok(new_token) => {
                let old_at = self.dao.keys().oauth2_token(&record.access_token);
                self.dao.delete(&old_at).await?;
                Ok(new_token)
            }
            Err(e) => {
                let ttl = Some(Duration::from_secs(self.refresh_token_ttl as u64));
                self.dao.set_string(&rt_key, &raw, ttl).await?;
                Err(e)
            }
        }
    }

    /// Revoke access and/or refresh token keys (errors propagate).
    /// 撤销访问/刷新令牌键（错误上抛）。
    pub async fn revoke_token(&self, token: &str) -> SaTokenResult<()> {
        let access_key = self.dao.keys().oauth2_token(token);
        let refresh_key = self.dao.keys().oauth2_refresh(token);
        self.dao.delete(&access_key).await?;
        self.dao.delete(&refresh_key).await?;
        Ok(())
    }

    /// Exact-match redirect URI validation (rejects empty / fragment).
    /// 精确匹配重定向 URI（拒绝空串 / fragment）。
    pub fn validate_redirect_uri(&self, client: &OAuth2Client, redirect_uri: &str) -> bool {
        if redirect_uri.is_empty() || redirect_uri.contains('#') {
            return false;
        }
        client.redirect_uris.iter().any(|uri| uri == redirect_uri)
    }

    /// True when every requested scope is registered on the client.
    /// 请求的每个 scope 均已在客户端注册时返回 true。
    pub fn validate_scope(&self, client: &OAuth2Client, requested_scope: &[String]) -> bool {
        requested_scope.iter().all(|s| client.scope.contains(s))
    }

    /// True when the client lists the grant type.
    /// 客户端声明了该授权类型时返回 true。
    pub fn supports_grant_type(client: &OAuth2Client, grant_type: &str) -> bool {
        client.grant_types.iter().any(|g| g == grant_type)
    }

    /// Resource-owner password grant (requires injected verifier).
    /// 资源所有者密码模式（需注入校验器）。
    pub async fn password_grant(
        &self,
        client_id: &str,
        client_secret: &str,
        username: &str,
        password: &str,
        scope: Vec<String>,
    ) -> SaTokenResult<AccessToken> {
        let verifier = self.password_verifier.as_ref().ok_or_else(|| {
            SaTokenError::ConfigError("password verifier is not configured".into())
        })?;
        let client = self.get_client(client_id).await?;
        if !Self::supports_grant_type(&client, "password") {
            return Err(SaTokenError::OAuth2UnsupportedGrant);
        }
        if !self.verify_client(client_id, client_secret).await? {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }
        if !self.validate_scope(&client, &scope) {
            return Err(SaTokenError::OAuth2InvalidScope);
        }
        verifier.verify_password(username, password).await?;
        self.generate_access_token(client_id, username, scope).await
    }

    /// Client-credentials grant (confidential clients only).
    /// 客户端凭证模式（仅机密客户端）。
    pub async fn client_credentials_grant(
        &self,
        client_id: &str,
        client_secret: &str,
        scope: Vec<String>,
    ) -> SaTokenResult<AccessToken> {
        let client = self.get_client(client_id).await?;
        if !Self::supports_grant_type(&client, "client_credentials") {
            return Err(SaTokenError::OAuth2UnsupportedGrant);
        }
        if client.public_client {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }
        if !self.verify_client(client_id, client_secret).await? {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }
        if !self.validate_scope(&client, &scope) {
            return Err(SaTokenError::OAuth2InvalidScope);
        }
        let subject = format!("client:{client_id}");
        self.generate_access_token(client_id, &subject, scope).await
    }

    /// Dispatch token issuance by grant type.
    /// 按授权类型分发令牌签发。
    pub async fn issue_token(&self, req: TokenIssueRequest) -> SaTokenResult<AccessToken> {
        match req.grant_type.as_str() {
            "authorization_code" => {
                let code = req.code.ok_or(SaTokenError::OAuth2CodeNotFound)?;
                let redirect_uri = req
                    .redirect_uri
                    .ok_or(SaTokenError::OAuth2RedirectUriMismatch)?;
                self.exchange_code_for_token(
                    &code,
                    &req.client_id,
                    &req.client_secret,
                    &redirect_uri,
                    req.code_verifier.as_deref(),
                )
                .await
            }
            "refresh_token" => {
                let refresh = req
                    .refresh_token
                    .ok_or(SaTokenError::OAuth2RefreshTokenNotFound)?;
                self.refresh_access_token(&refresh, &req.client_id, &req.client_secret)
                    .await
            }
            "password" => {
                let username = req.username.ok_or(SaTokenError::OAuth2InvalidCredentials)?;
                let password = req.password.ok_or(SaTokenError::OAuth2InvalidCredentials)?;
                self.password_grant(
                    &req.client_id,
                    &req.client_secret,
                    &username,
                    &password,
                    req.scope,
                )
                .await
            }
            "client_credentials" => {
                self.client_credentials_grant(&req.client_id, &req.client_secret, req.scope)
                    .await
            }
            _ => Err(SaTokenError::OAuth2UnsupportedGrant),
        }
    }

    /// Validate client + redirect + scope + PKCE, then generate and store a code.
    /// 校验客户端 / 重定向 / scope / PKCE 后生成并存储授权码。
    pub async fn issue_authorization_code(
        &self,
        client_id: String,
        user_id: String,
        redirect_uri: String,
        scope: Vec<String>,
        pkce: Option<PkceChallenge>,
        state: Option<String>,
    ) -> SaTokenResult<AuthorizationCode> {
        let client = self.get_client(&client_id).await?;
        if !self.validate_redirect_uri(&client, &redirect_uri) {
            return Err(SaTokenError::OAuth2RedirectUriMismatch);
        }
        if !self.validate_scope(&client, &scope) {
            return Err(SaTokenError::OAuth2InvalidScope);
        }
        if (client.public_client || self.require_pkce) && pkce.is_none() {
            return Err(if client.public_client {
                SaTokenError::OAuth2PkceRequiredForPublicClient
            } else {
                SaTokenError::OAuth2PkceRequired
            });
        }
        let code =
            self.generate_authorization_code(client_id, user_id, redirect_uri, scope, pkce, state);
        self.store_authorization_code(&code).await?;
        Ok(code)
    }
}
