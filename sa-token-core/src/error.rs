// Author: 金书记
//
//! Error type definitions | 错误类型定义

use thiserror::Error;

/// Result alias for core operations | 核心操作结果别名
pub type SaTokenResult<T> = Result<T, SaTokenError>;

/// Unified error type for sa-token-core | sa-token-core 统一错误类型
#[derive(Debug, Error)]
pub enum SaTokenError {
    // ============ Basic Token Errors | 基础 Token 错误 ============
    /// Token not found or expired | Token 不存在或已过期
    #[error("Token not found or expired")]
    TokenNotFound,

    /// Token value is invalid | Token 值无效
    #[error("Token is invalid: {0}")]
    InvalidToken(String),

    /// Token has expired | Token 已过期
    #[error("Token has expired")]
    TokenExpired,

    // ============ Authentication Errors | 认证错误 ============
    /// Caller is not logged in | 当前未登录
    #[error("User not logged in")]
    NotLogin,

    /// Token exists but is inactive | Token 存在但未激活
    #[error("Token is inactive")]
    TokenInactive,

    // ============ Authorization Errors | 授权错误 ============
    /// Permission check failed | 权限校验失败
    #[error("Permission denied")]
    PermissionDenied,

    /// Missing a specific permission | 缺少指定权限
    #[error("Permission denied: missing permission '{0}'")]
    PermissionDeniedDetail(String),

    /// Missing a specific role | 缺少指定角色
    #[error("Role denied: missing role '{0}'")]
    RoleDenied(String),

    // ============ Account Status Errors | 账户状态错误 ============
    /// Account is banned until the given time | 账号被封禁至指定时间
    #[error("Account is banned until {0}")]
    AccountBanned(String),

    /// Account was kicked out | 账号已被踢下线
    #[error("Account is kicked out")]
    AccountKickedOut,

    /// Login was replaced on another device | 账号在其他设备顶替登录
    #[error("Account login has been replaced on another device")]
    AccountReplaced,

    /// Secondary authentication required | 需要二次认证
    #[error("Secondary authentication required for service '{0}'")]
    NotSafe(String),

    /// Account disabled for a service at a level | 账号在某服务下被禁用
    #[error("Account is disabled for service '{service}' at level {level}")]
    DisableService {
        /// Service name | 服务名
        service: String,
        /// Disable level | 禁用等级
        level: i32,
    },

    // ============ Session Errors | Session 错误 ============
    /// Session not found | Session 不存在
    #[error("Session not found")]
    SessionNotFound,

    // ============ Nonce Errors | Nonce 错误 ============
    /// Nonce already consumed (possible replay) | Nonce 已使用（疑似重放）
    #[error("Nonce has been used, possible replay attack detected")]
    NonceAlreadyUsed,

    /// Nonce format is invalid | Nonce 格式无效
    #[error("Invalid nonce format")]
    InvalidNonceFormat,

    /// Nonce timestamp invalid or expired | Nonce 时间戳无效或过期
    #[error("Nonce timestamp is invalid or expired")]
    InvalidNonceTimestamp,

    // ============ Refresh Token Errors | 刷新令牌错误 ============
    /// Refresh token missing or expired | 刷新令牌不存在或过期
    #[error("Refresh token not found or expired")]
    RefreshTokenNotFound,

    /// Refresh token payload invalid | 刷新令牌数据无效
    #[error("Invalid refresh token data")]
    RefreshTokenInvalidData,

    /// Refresh token missing login_id | 刷新令牌缺少 login_id
    #[error("Missing login_id in refresh token")]
    RefreshTokenMissingLoginId,

    /// Refresh token expire time format invalid | 刷新令牌过期时间格式无效
    #[error("Invalid expire time format in refresh token")]
    RefreshTokenInvalidExpireTime,

    // ============ Token Validation Errors | Token 验证错误 ============
    /// Token string is empty | Token 为空
    #[error("Token is empty")]
    TokenEmpty,

    /// Token string is too short | Token 过短
    #[error("Token is too short")]
    TokenTooShort,

    /// Login id is not a valid number | 登录 ID 不是合法数字
    #[error("Login ID is not a valid number")]
    LoginIdNotNumber,

    // ============ OAuth2 Errors | OAuth2 错误 ============
    /// OAuth2 client not found | OAuth2 客户端不存在
    #[error("OAuth2 client not found")]
    OAuth2ClientNotFound,

    /// Invalid OAuth2 client credentials | OAuth2 客户端凭据无效
    #[error("Invalid client credentials")]
    OAuth2InvalidCredentials,

    /// OAuth2 client id mismatch | OAuth2 客户端 ID 不匹配
    #[error("Client ID mismatch")]
    OAuth2ClientIdMismatch,

    /// OAuth2 redirect URI mismatch | OAuth2 回调地址不匹配
    #[error("Redirect URI mismatch")]
    OAuth2RedirectUriMismatch,

    /// Authorization code missing or expired | 授权码不存在或过期
    #[error("Authorization code not found or expired")]
    OAuth2CodeNotFound,

    /// Access token missing or expired | 访问令牌不存在或过期
    #[error("Access token not found or expired")]
    OAuth2AccessTokenNotFound,

    /// Refresh token missing or expired | 刷新令牌不存在或过期
    #[error("Refresh token not found or expired")]
    OAuth2RefreshTokenNotFound,

    /// Invalid OAuth2 refresh token data | OAuth2 刷新令牌数据无效
    #[error("Invalid refresh token data")]
    OAuth2InvalidRefreshToken,

    /// Invalid OAuth2 scope data | OAuth2 scope 数据无效
    #[error("Invalid scope data")]
    OAuth2InvalidScope,

    /// PKCE code_verifier required | 需要 PKCE code_verifier
    #[error("OAuth2 PKCE code_verifier required")]
    OAuth2PkceRequired,

    /// PKCE verification failed | PKCE 校验失败
    #[error("OAuth2 PKCE verification failed")]
    OAuth2PkceMismatch,

    /// Token revoke failed | 令牌吊销失败
    #[error("OAuth2 token revoke failed: {0}")]
    OAuth2TokenRevokeFailed(String),

    /// Unsupported OAuth2 grant type | 不支持的授权类型
    #[error("OAuth2 unsupported grant type")]
    OAuth2UnsupportedGrant,

    /// Public client must use PKCE S256 | 公共客户端必须使用 PKCE S256
    #[error("OAuth2 public client must use PKCE S256")]
    OAuth2PkceRequiredForPublicClient,

    // ============ SSO Errors | SSO 单点登录错误 ============
    /// SSO ticket not found or invalid | SSO ticket 不存在或无效
    #[error("SSO ticket not found or invalid")]
    InvalidTicket,

    /// SSO ticket expired | SSO ticket 已过期
    #[error("SSO ticket has expired")]
    TicketExpired,

    /// Service URL mismatch | 服务地址不匹配
    #[error("Service URL mismatch")]
    ServiceMismatch,

    /// SSO session not found | SSO 会话不存在
    #[error("SSO session not found")]
    SsoSessionNotFound,

    /// SSO request signature invalid | SSO 请求签名无效
    #[error("SSO request signature invalid")]
    SsoSignInvalid,

    /// Device / terminal type is not allowed.
    /// 设备/终端类型不允许。
    #[error("Terminal denied: expected '{expected}', actual '{actual}'")]
    TerminalDenied {
        /// Allowed terminal pattern | 允许的终端模式
        expected: String,
        /// Actual terminal value | 实际终端值
        actual: String,
    },

    /// Same-Token header missing or not matching current/past token.
    /// Same-Token 头缺失或与当前/宽限 token 不一致。
    #[error("Invalid same-token")]
    SameTokenInvalid,

    /// HTTP Basic credentials missing or mismatch.
    /// HTTP Basic 凭据缺失或不匹配。
    #[error("HTTP Basic authentication failed")]
    BasicAuthFailed {
        /// Auth realm for WWW-Authenticate | WWW-Authenticate 的 realm
        realm: String,
    },

    /// Request signature does not match.
    /// 请求签名不匹配。
    #[error("Invalid request signature")]
    SignInvalid,

    /// Request `timestamp` missing or outside the allowed window.
    /// 请求 `timestamp` 缺失或超出允许窗口。
    #[error("Request signature timestamp is invalid or expired")]
    SignTimestampExpired,

    /// Temp token missing or already deleted.
    /// 临时令牌不存在或已删除。
    #[error("Temp token not found")]
    TempTokenNotFound,

    /// Temp token past expire_at.
    /// 临时令牌已过 expire_at。
    #[error("Temp token has expired")]
    TempTokenExpired,

    // ============ Lifecycle Errors | 生命周期错误 ============
    /// 全局 Manager 尚未初始化
    /// Global manager has not been initialized
    #[error("Sa-Token manager is not initialized; call StpUtil::try_init_manager() first")]
    NotInitialized,

    /// 全局 Manager 重复初始化
    /// Global manager was already initialized
    #[error("Sa-Token manager is already initialized")]
    AlreadyInitialized,

    // ============ System Errors | 系统错误 ============
    /// Underlying storage failure | 底层存储失败
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Invalid configuration | 配置无效
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Serialization / deserialization failure | 序列化或反序列化失败
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Unexpected internal failure | 未预期的内部错误
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<serde_json::Error> for SaTokenError {
    fn from(value: serde_json::Error) -> Self {
        Self::SerializationError(value.to_string())
    }
}

impl From<sa_token_adapter::serializer::SerializerError> for SaTokenError {
    fn from(value: sa_token_adapter::serializer::SerializerError) -> Self {
        Self::SerializationError(value.to_string())
    }
}

impl SaTokenError {
    /// Get the error message as a string.
    ///
    /// Returns the English message from `#[error(...)]`.
    /// 返回 `#[error(...)]` 定义的英文文案。
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let err = SaTokenError::NotLogin;
    /// assert_eq!(err.message(), "User not logged in");
    /// ```
    pub fn message(&self) -> String {
        self.to_string()
    }

    /// Whether this is an authentication (login/token) error.
    /// 是否为认证（登录/Token）类错误。
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            Self::NotLogin
                | Self::TokenNotFound
                | Self::TokenExpired
                | Self::TokenInactive
                | Self::InvalidToken(_)
                | Self::AccountKickedOut
                | Self::AccountReplaced
        )
    }

    /// Whether this is an authorization (permission/role) error.
    /// 是否为授权（权限/角色）类错误。
    pub fn is_authz_error(&self) -> bool {
        matches!(
            self,
            Self::PermissionDenied | Self::PermissionDeniedDetail(_) | Self::RoleDenied(_)
        )
    }
}

/// Application-level error messages | 应用层标准错误文案
///
/// Constants for app-specific errors that are not part of [`SaTokenError`].
/// 供业务侧使用的标准短文案（非 [`SaTokenError`] 变体）。
///
/// # Examples
///
/// ```rust,ignore
/// use sa_token_core::error::messages;
///
/// let err_msg = messages::INVALID_CREDENTIALS;
/// return Err(ApiError::Unauthorized(err_msg.to_string()));
/// ```
pub mod messages {
    /// Invalid username or password | 用户名或密码错误
    pub const INVALID_CREDENTIALS: &str = "Invalid username or password";

    /// Login failed | 登录失败
    pub const LOGIN_FAILED: &str = "Login failed";

    /// Authentication error | 认证错误
    pub const AUTH_ERROR: &str = "Authentication error";

    /// Permission required | 需要权限
    pub const PERMISSION_REQUIRED: &str = "Permission required";

    /// Role required | 需要角色
    pub const ROLE_REQUIRED: &str = "Role required";

    /// HTTP Basic authentication failed | HTTP Basic 认证失败
    pub const BASIC_AUTH_FAILED: &str = "HTTP Basic authentication failed";
}
