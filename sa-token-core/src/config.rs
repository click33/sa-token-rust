// Author: 金书记
//
//! 配置模块 | Configuration module

use crate::error::{SaTokenError, SaTokenResult};
use crate::event::{SaTokenEventBus, SaTokenListener};
use crate::keys::SaKeyLayout;
use sa_token_adapter::serializer::SharedSerializer;
use sa_token_adapter::storage::SaStorage;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::Arc;
use std::time::Duration;

/// sa-token 全局配置。
/// Global sa-token configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaTokenConfig {
    /// Token 名称（header / cookie / body 中的键名）
    /// Token name (key used in header, cookie, or body)
    pub token_name: String,

    /// Token 有效期（秒），`-1` 表示永久有效
    /// Token lifetime in seconds; `-1` means never expires
    pub timeout: i64,

    /// Token 最低活跃频率（秒），`-1` 表示不限制。
    /// 超过该间隔未活跃则冻结（`TokenInactive`）；开启 `auto_renew` 时亦用于续签时长。
    ///
    /// Minimum activity interval in seconds; `-1` disables the check.
    /// Idle longer than this freezes the token (`TokenInactive`); also used as
    /// the renewal window when `auto_renew` is enabled.
    pub active_timeout: i64,

    /// Per-token activity window override.
    /// 是否启用逐 token 的活跃窗口覆盖。
    pub dynamic_active_timeout: bool,

    /// 是否开启自动续签（0.2.0 起默认 `false`，避免每次读 token 都写存储）
    /// Whether to enable auto-renewal (defaults to `false` since 0.2.0 to avoid
    /// a storage write on every token read)
    pub auto_renew: bool,

    /// 续签阈值（秒）：仅当 token 剩余有效时间低于该值时才真正触发续签写入。
    ///
    /// 语义（三段）：
    /// - `< 0`（如 `-1`）：不启用阈值，每次读取都续签 —— 兼容 0.1.x 旧行为
    /// - `== 0`：仅当剩余时间 `<= 0`（已到期边界）才续签
    /// - `> 0`：剩余时间 `<=` 阈值时才续签（推荐，默认 `300`）
    ///
    /// 注意：本字段仅在 `auto_renew == true` 时生效。
    ///
    /// Renewal threshold in seconds: a renewal write happens only when the
    /// token's remaining lifetime drops below this value.
    /// - `< 0`: threshold disabled, renew on every read (0.1.x behaviour)
    /// - `== 0`: renew only when remaining lifetime `<= 0`
    /// - `> 0`: renew when remaining lifetime `<=` threshold (recommended; default `300`)
    ///
    /// Only effective when `auto_renew == true`.
    pub renew_threshold: i64,

    /// 是否允许同一账号并发登录
    /// Whether the same account may log in concurrently
    pub is_concurrent: bool,

    /// Concurrent logins share one token when true (default `false`).
    /// 为 true 时同一账号并发登录共用一个 token（默认 `false`）。
    pub is_share: bool,

    /// Token 风格（uuid、simple-uuid、random-32、random-64、random-128 等）
    /// Token generation style (uuid, simple-uuid, random-32/64/128, etc.)
    pub token_style: TokenStyle,

    /// 是否输出操作日志
    /// Whether to emit operation logs
    pub is_log: bool,

    /// 是否从 cookie 中读取 token
    /// Whether to read the token from cookies
    pub is_read_cookie: bool,

    /// 是否从 header 中读取 token
    /// Whether to read the token from headers
    pub is_read_header: bool,

    /// 是否从请求体中读取 token
    /// Whether to read the token from the request body
    pub is_read_body: bool,

    /// Optional token prefix. `None` = still strip a leading `Bearer `.
    /// 可选 token 前缀。`None` 时仍剥离开头的 `Bearer `。
    #[serde(default)]
    pub token_prefix: Option<String>,

    /// Cookie write settings (opt-in).
    /// Cookie 下发配置（默认不写）。
    #[serde(default)]
    pub cookie: TokenCookieConfig,

    /// JWT 密钥（使用 JWT 风格时）
    /// JWT secret key (when using the JWT token style)
    pub jwt_secret_key: Option<String>,

    /// JWT 算法（默认 `HS256`）
    /// JWT algorithm (default `HS256`)
    pub jwt_algorithm: Option<String>,

    /// JWT 签发者（`iss`）
    /// JWT issuer (`iss`)
    pub jwt_issuer: Option<String>,

    /// JWT 受众（`aud`）
    /// JWT audience (`aud`)
    pub jwt_audience: Option<String>,

    /// JWT 生成失败时是否回退为 UUID（默认 `false`）；失败时始终记录日志
    /// Whether to fall back to UUID when JWT generation fails (default `false`); always log on failure
    pub jwt_fallback_on_error: bool,

    /// 是否启用防重放攻击（nonce 机制）
    /// Whether to enable anti-replay protection via nonce
    pub enable_nonce: bool,

    /// Nonce 有效期（秒），`-1` 表示沿用 token `timeout`
    /// Nonce lifetime in seconds; `-1` follows token `timeout`
    pub nonce_timeout: i64,

    /// 是否启用 Refresh Token
    /// Whether to enable refresh tokens
    pub enable_refresh_token: bool,

    /// Refresh Token 有效期（秒），默认 7 天（`604800`）
    /// Refresh-token lifetime in seconds (default 7 days / `604800`)
    pub refresh_token_timeout: i64,

    /// 存储键前缀（Redis / 数据库等后端的键命名）。
    /// 默认 `"sa:"`，所有逻辑键以此为前缀，如 `"sa:token:"`、`"sa:session:"`。
    ///
    /// Storage key prefix for Redis/DB backends.
    /// Default `"sa:"`; all logical keys are prefixed, e.g. `"sa:token:"`, `"sa:session:"`.
    pub storage_key_prefix: String,

    /// 存储键布局策略（A3-1）
    /// Storage key layout strategy (A3-1)
    #[serde(default)]
    pub key_layout: SaKeyLayout,

    /// 同一账号最大登录数量，`-1` 表示不限制
    /// Max concurrent logins per account; `-1` means unlimited
    pub max_login_count: i64,

    /// 超出 `max_login_count` 时的下线模式
    /// Logout mode used when `max_login_count` is exceeded
    pub overflow_logout_mode: LogoutMode,

    /// 非并发顶号时：踢旧设备还是拒绝新登录
    /// Non-concurrent replace policy: kick the old device or reject the new login
    pub replaced_login_exit_mode: ReplacedLoginExitMode,

    /// Replace scope on non-concurrent login (already enforced in AuthService).
    /// 非并发顶号范围（AuthService 已落地）。
    pub replaced_range: ReplacedRange,

    /// 登录时是否立即创建 Token-Session
    /// Whether to create a Token-Session immediately on login
    pub right_now_create_token_session: bool,

    /// 获取 Token-Session 时是否校验 token 登录态
    /// Whether fetching a Token-Session requires a valid login
    pub token_session_check_login: bool,

    /// Default logout range: current token or entire account.
    /// 默认 logout 范围：当前 token 或整个账号。
    pub logout_range: LogoutRange,

    /// logout 时是否保留 Token-Session
    /// Whether to keep the Token-Session on logout
    pub is_logout_keep_token_session: bool,

    /// 权限/角色读缓存 TTL（秒）。`<= 0` 表示**关闭缓存**（默认），此时不分配任何缓存结构。
    ///
    /// 关闭是默认值的理由：多实例部署下缓存会带来「权限变更滞后」的安全窗口，
    /// 必须由使用者显式权衡后开启，而不是默认埋一个隐患。
    ///
    /// TTL in seconds for the permission/role read cache. `<= 0` disables the
    /// cache entirely (default) and allocates nothing. Disabled by default
    /// because a multi-instance deployment would otherwise silently inherit a
    /// staleness window for authorization decisions.
    #[serde(default)]
    pub grant_cache_ttl: i64,

    /// 权限/角色缓存的**总条目上限**（跨全部分片）。达到上限时先清过期项，
    /// 仍超限则淘汰「最早过期」的一项，保证内存有界。
    ///
    /// Global upper bound on cached entries across all shards. On overflow the
    /// cache first drops expired entries, then evicts the soonest-to-expire
    /// one, keeping memory bounded.
    #[serde(default = "default_grant_cache_max_entries")]
    pub grant_cache_max_entries: usize,

    /// 是否启用**单飞**（single-flight）：同一 key 并发未命中时只放行一次底层加载，
    /// 其余请求等待复用结果，避免缓存击穿打爆外部数据源。
    ///
    /// Enables single-flight: concurrent misses on the same key trigger only one
    /// underlying load, preventing a cache stampede against the data source.
    #[serde(default = "default_true")]
    pub grant_cache_single_flight: bool,

    /// 是否启用**请求级授权快照**：同一请求（`SaTokenContext::scope`）内多次鉴权
    /// 只读一次数据源。与 TTL 缓存不同，它随请求结束即销毁，**没有一致性窗口**，
    /// 因此默认开启。
    ///
    /// Enables a per-request authorization snapshot so repeated checks inside one
    /// `SaTokenContext::scope` hit the data source once. Unlike the TTL cache it
    /// dies with the request, so there is no staleness window — hence on by default.
    #[serde(default = "default_true")]
    pub grant_request_scope: bool,

    /// 注入只读 `StpInterface` 时的写策略，见 [`GrantWritePolicy`]。
    /// Write policy when a read-only `StpInterface` is injected.
    #[serde(default)]
    pub grant_write_policy: GrantWritePolicy,

    /// When true, role checks honour `*` wildcards (default `false` = exact).
    /// 为 true 时角色校验识别 `*` 通配（默认 `false`，精确匹配）。
    ///
    /// Enabling routes roles through the same segment matcher used for permissions.
    #[serde(default)]
    pub role_wildcard: bool,

    // ========== 上下文行为 | Context Behavior ==========
    /// `with_current_mut` 在无上下文时是否自动创建空上下文（默认 false，返回 None）
    ///
    /// When `true`, `with_current_mut` auto-creates an empty context if none exists (fallback for
    /// sync paths); when `false` (default), returns `None` to surface the programming error.
    #[serde(default)]
    pub context_auto_create: bool,

    /// HTTP Basic account in `user:password` form. Empty = caller must pass account.
    /// HTTP Basic 账号，格式 `user:password`。空表示调用方必须传入 account。
    #[serde(default)]
    pub http_basic: String,

    /// Same-Token TTL in seconds; `<= 0` means no TTL (storage-dependent).
    /// Same-Token 有效期（秒）；`<= 0` 表示不设 TTL。
    #[serde(default = "default_same_token_timeout")]
    pub same_token_timeout: i64,

    /// Header name for Same-Token.
    /// Same-Token 请求头名。
    #[serde(default = "default_same_token_header")]
    pub same_token_header: String,

    /// Max attempts when allocating a unique login / temp token. `-1` = do not retry.
    /// 分配唯一登录/临时 token 的最大尝试次数。`-1` 表示不重试。
    #[serde(default = "default_max_try_times")]
    pub max_try_times: i32,

    /// HMAC secret for `RequestSign` via StpUtil (independent from JWT).
    /// StpUtil 使用的 HMAC 密钥（与 JWT 密钥分离）。
    #[serde(default)]
    pub sign_secret_key: Option<String>,

    /// Timestamp window in seconds for `RequestSign` (default 300).
    /// `RequestSign` 的时间窗（秒），默认 300。
    #[serde(default = "default_sign_window_secs")]
    pub sign_window_secs: i64,

    /// 存储层序列化器（默认 JSON；可选 fory；不参与本结构的 serde 序列化）
    /// Storage serializer (JSON by default; optional fory; skipped by this struct's serde)
    #[serde(skip, default)]
    pub serializer: SharedSerializer,
}

/// serde 默认值：缓存条目上限。4096 条 ≈ 4096 个活跃账号的权限列表。
/// serde default for the cache capacity; 4096 active accounts is a safe baseline.
fn default_grant_cache_max_entries() -> usize {
    4096
}

/// serde 默认值：布尔真（serde 对 `bool` 的 `default` 是 `false`，需显式函数）
/// serde default for `true`, since serde's `bool` default is `false`.
fn default_true() -> bool {
    true
}

fn default_same_token_timeout() -> i64 {
    86400
}

fn default_same_token_header() -> String {
    "SA-SAME-TOKEN".to_string()
}

fn default_max_try_times() -> i32 {
    12
}

fn default_sign_window_secs() -> i64 {
    300
}

fn default_true_cookie_http_only() -> bool {
    true
}

/// Cookie attributes used when a handler opts into writing the token cookie.
/// Handler 选择写入 token Cookie 时使用的属性。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCookieConfig {
    /// When false, `write_token_cookie` is a no-op (default).
    /// 为 false 时 `write_token_cookie` 为空操作（默认）。
    #[serde(default)]
    pub is_write_cookie: bool,
    /// `domain` | `domain`
    pub domain: Option<String>,
    /// `path` | `path`
    pub path: Option<String>,
    #[serde(default = "default_true_cookie_http_only")]
    /// `http_only` | `http_only`
    pub http_only: bool,
    #[serde(default)]
    /// `secure` | `secure`
    pub secure: bool,
    /// `same_site` | `same_site`
    pub same_site: Option<sa_token_adapter::context::SameSite>,
}

impl Default for TokenCookieConfig {
    fn default() -> Self {
        Self {
            is_write_cookie: false,
            domain: None,
            path: Some("/".into()),
            http_only: true,
            secure: false,
            same_site: Some(sa_token_adapter::context::SameSite::Lax),
        }
    }
}

impl Default for SaTokenConfig {
    fn default() -> Self {
        Self {
            token_name: "sa-token".to_string(),
            timeout: 2592000, // 30 天 | 30 days
            active_timeout: -1,
            dynamic_active_timeout: false,
            // B1：默认关闭自动续签，避免每次读 token 都写存储
            // B1: auto-renew off by default to avoid a write on every token read
            auto_renew: false,
            renew_threshold: 300,
            is_concurrent: true,
            is_share: false,
            token_style: TokenStyle::Uuid,
            is_log: false,
            is_read_cookie: true,
            is_read_header: true,
            is_read_body: true,
            token_prefix: None,
            cookie: TokenCookieConfig::default(),
            jwt_secret_key: None,
            jwt_algorithm: Some("HS256".to_string()),
            jwt_issuer: None,
            jwt_audience: None,
            jwt_fallback_on_error: false, // 0.2.0：失败必须可见，禁止静默 UUID
            enable_nonce: false,
            nonce_timeout: -1,
            enable_refresh_token: false,
            refresh_token_timeout: 604800, // 7 天 | 7 days
            storage_key_prefix: "sa:".to_string(),
            key_layout: SaKeyLayout::ThreeSegment,
            max_login_count: -1,
            overflow_logout_mode: LogoutMode::Logout,
            replaced_login_exit_mode: ReplacedLoginExitMode::OldDevice,
            replaced_range: ReplacedRange::CurrDeviceType,
            right_now_create_token_session: false,
            token_session_check_login: true,
            logout_range: LogoutRange::Token,
            is_logout_keep_token_session: false,
            grant_cache_ttl: 0,
            grant_cache_max_entries: default_grant_cache_max_entries(),
            grant_cache_single_flight: true,
            grant_request_scope: true,
            grant_write_policy: GrantWritePolicy::Warn,
            role_wildcard: false,
            context_auto_create: false,
            http_basic: String::new(),
            same_token_timeout: 86400,
            same_token_header: "SA-SAME-TOKEN".to_string(),
            max_try_times: 12,
            sign_secret_key: None,
            sign_window_secs: 300,
            serializer: SharedSerializer::default(),
        }
    }
}

impl SaTokenConfig {
    /// 创建配置构建器 | Create a configuration builder
    pub fn builder() -> SaTokenConfigBuilder {
        SaTokenConfigBuilder::default()
    }

    /// 将 `timeout` 转为 `Duration`；永久（`< 0`）时返回 `None`
    /// Convert `timeout` to a `Duration`; returns `None` when permanent (`< 0`)
    pub fn timeout_duration(&self) -> Option<Duration> {
        if self.timeout < 0 {
            None
        } else {
            Some(Duration::from_secs(self.timeout as u64))
        }
    }

    /// Reject Jwt style without a usable secret. Call from builders.
    /// Jwt 风格必须带可用密钥。由 builder 调用。
    pub fn validate_jwt(&self) -> SaTokenResult<()> {
        if matches!(self.token_style, TokenStyle::Jwt) {
            match self.jwt_secret_key.as_deref() {
                Some(s) if !s.trim().is_empty() => Ok(()),
                _ => Err(SaTokenError::ConfigError(
                    "jwt_secret_key required for Jwt token style".into(),
                )),
            }
        } else {
            Ok(())
        }
    }

    /// Reject unusable token-read / prefix combinations.
    /// 拒绝无法工作的读取开关 / 前缀组合。
    pub fn validate_token_io(&self) -> SaTokenResult<()> {
        if !self.is_read_header && !self.is_read_cookie && !self.is_read_body {
            return Err(SaTokenError::ConfigError(
                "at least one of is_read_header, is_read_cookie, is_read_body must be true".into(),
            ));
        }
        if let Some(p) = self.token_prefix.as_deref() {
            if p.is_empty() {
                return Err(SaTokenError::ConfigError(
                    "token_prefix cannot be empty; use None to disable a custom prefix".into(),
                ));
            }
        }
        Ok(())
    }

    /// 权限缓存 TTL 的 `Duration` 形式；返回 `None` 表示**不启用缓存**。
    ///
    /// The grant cache TTL as a `Duration`; `None` means the cache is disabled.
    pub fn grant_cache_duration(&self) -> Option<Duration> {
        if self.grant_cache_ttl > 0 {
            Some(Duration::from_secs(self.grant_cache_ttl as u64))
        } else {
            None
        }
    }

    /// 构造存储键：拼接 `storage_key_prefix` 与后缀。
    /// Build a storage key by joining `storage_key_prefix` and a suffix.
    ///
    /// # Deprecated
    ///
    /// 请改用 [`SaKeys`] 具名方法，以尊重键布局策略。
    /// Use [`SaKeys`] named methods instead so key layout is respected.
    #[deprecated(
        since = "0.2.0",
        note = "Use SaKeys named key methods (token_info / login_token / ...) instead"
    )]
    pub fn make_key(&self, suffix: &str, id: &str) -> String {
        format!("{}{}{}", self.storage_key_prefix, suffix, id)
    }

    /// 获取存储键前缀 | Get the storage key prefix
    pub fn key_prefix(&self) -> &str {
        &self.storage_key_prefix
    }

    /// 将领域对象编码为存储字符串 | Encode a domain object into a storage string
    pub fn encode<T: Serialize + ?Sized>(&self, value: &T) -> SaTokenResult<String> {
        self.serializer
            .encode(value)
            .map_err(|e| SaTokenError::SerializationError(e.to_string()))
    }

    /// 从存储字符串解码领域对象 | Decode a domain object from a storage string
    pub fn decode<T: DeserializeOwned>(&self, raw: &str) -> SaTokenResult<T> {
        self.serializer
            .decode(raw)
            .map_err(|e| SaTokenError::SerializationError(e.to_string()))
    }
}

/// Token 风格 | Token style
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TokenStyle {
    /// UUID 风格 | UUID style
    Uuid,
    /// 简化 UUID（去掉横杠）| Simple UUID (without hyphens)
    SimpleUuid,
    /// 32 位随机字符串 | 32-character random string
    Random32,
    /// 64 位随机字符串 | 64-character random string
    Random64,
    /// 128 位随机字符串 | 128-character random string
    Random128,
    /// JWT 风格（JSON Web Token）| JWT style (JSON Web Token)
    Jwt,
    /// Hash 风格（SHA256）| Hash style (SHA256)
    Hash,
    /// 时间戳风格（毫秒时间戳 + 随机数）| Timestamp style (ms timestamp + random)
    Timestamp,
    /// Tik 风格（短小的 8 位字符）| Tik style (short 8-character token)
    Tik,
}

/// How a session is ended: normal logout, kick-out, or replaced.
/// 会话结束方式：正常登出、踢下线、或顶号替换。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LogoutMode {
    /// 正常登出 | Normal logout
    #[default]
    Logout,
    /// 踢下线（标记 `-5`）| Kick out (marker `-5`)
    KickOut,
    /// 顶下线（标记 `-4`）| Replaced / bumped offline (marker `-4`)
    Replaced,
}

/// 非并发顶号时：踢旧设备还是拒绝新登录
/// Non-concurrent replace policy: kick old device or reject new login
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ReplacedLoginExitMode {
    /// 踢掉旧设备，允许新登录 | Kick the old device and allow the new login
    #[default]
    OldDevice,
    /// 拒绝新登录，保留旧设备 | Reject the new login and keep the old device
    NewDevice,
}

/// 顶号影响范围 | Scope of a replace (bump) operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ReplacedRange {
    /// 仅当前设备类型 | Current device type only
    #[default]
    CurrDeviceType,
    /// 全部设备类型 | All device types
    AllDeviceType,
}

/// 注入只读 `StpInterface` 时，权限/角色**写操作**的处理策略。
///
/// Write policy for permission/role mutations when a **read-only**
/// `StpInterface` is injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum GrantWritePolicy {
    /// 静默写入 storage，不告警
    /// Write to storage silently; use only when the caller knows the trade-off.
    Allow,

    /// 写入 storage 并输出 `tracing::warn!`（默认，向后兼容且不静默）
    /// Write to storage and emit a `tracing::warn!`. Default: compatible, not silent.
    #[default]
    Warn,

    /// 直接拒绝写操作，返回 `SaTokenError::ConfigError`
    /// Reject the write outright with `SaTokenError::ConfigError`.
    Reject,
}

/// Logout range for [`AuthService::logout`] / default config.
/// [`AuthService::logout`] / 默认配置使用的登出范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LogoutRange {
    /// Current token only | 仅当前 token
    #[default]
    Token,
    /// Entire account | 整个账号
    Account,
}

/// 配置构建器 | Configuration builder
#[derive(Default)]
pub struct SaTokenConfigBuilder {
    /// 累积中的配置 | Accumulated configuration
    config: SaTokenConfig,
    /// 可选存储适配器 | Optional storage adapter
    storage: Option<Arc<dyn SaStorage>>,
    /// 待注册的事件监听器 | Event listeners to register on build
    listeners: Vec<Arc<dyn SaTokenListener>>,
    /// 可选序列化器覆盖 | Optional serializer override
    serializer: Option<SharedSerializer>,
    /// 可选共享事件总线 | Optional shared event bus
    event_bus: Option<SaTokenEventBus>,
}

impl std::fmt::Debug for SaTokenConfigBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SaTokenConfigBuilder { .. }")
    }
}

impl SaTokenConfigBuilder {
    /// 设置 Token 名称 | Set the token name
    pub fn token_name(mut self, name: impl Into<String>) -> Self {
        self.config.token_name = name.into();
        self
    }

    /// 设置 Token 有效期（秒）| Set token lifetime in seconds
    pub fn timeout(mut self, timeout: i64) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// 设置最低活跃频率（秒）| Set the minimum activity interval in seconds
    pub fn active_timeout(mut self, timeout: i64) -> Self {
        self.config.active_timeout = timeout;
        self
    }

    /// 设置是否启用 per-token 动态 `active_timeout`
    /// Enable or disable per-token dynamic `active_timeout`
    pub fn dynamic_active_timeout(mut self, enabled: bool) -> Self {
        self.config.dynamic_active_timeout = enabled;
        self
    }

    /// 设置是否开启自动续签 | Enable or disable auto-renewal
    pub fn auto_renew(mut self, enabled: bool) -> Self {
        self.config.auto_renew = enabled;
        self
    }

    /// 设置续签阈值（秒）。传入负值等价于关闭阈值（每次读取都续签）。
    /// Set the renewal threshold in seconds. A negative value disables the
    /// threshold, restoring the legacy "renew on every read" behaviour.
    pub fn renew_threshold(mut self, seconds: i64) -> Self {
        self.config.renew_threshold = seconds;
        self
    }

    /// 设置是否允许并发登录 | Enable or disable concurrent logins
    pub fn is_concurrent(mut self, concurrent: bool) -> Self {
        self.config.is_concurrent = concurrent;
        self
    }

    /// 设置是否共享 token | Enable or disable shared tokens across concurrent logins
    pub fn is_share(mut self, share: bool) -> Self {
        self.config.is_share = share;
        self
    }

    /// 设置 Token 风格 | Set the token generation style
    pub fn token_style(mut self, style: TokenStyle) -> Self {
        self.config.token_style = style;
        self
    }

    /// Emit operation logs at info level when true.
    /// 为 true 时在 info 级别输出操作日志。
    pub fn is_log(mut self, enabled: bool) -> Self {
        self.config.is_log = enabled;
        self
    }

    /// Read token from headers (including Authorization fallback).
    /// 是否从请求头读取 token（含 Authorization 回退）。
    pub fn is_read_header(mut self, enabled: bool) -> Self {
        self.config.is_read_header = enabled;
        self
    }

    /// Read token from cookies.
    /// 是否从 Cookie 读取 token。
    pub fn is_read_cookie(mut self, enabled: bool) -> Self {
        self.config.is_read_cookie = enabled;
        self
    }

    /// Read token from query/param (`is_read_body` name kept for compatibility).
    /// 是否从 query/param 读取 token（字段名 `is_read_body` 保持兼容）。
    pub fn is_read_body(mut self, enabled: bool) -> Self {
        self.config.is_read_body = enabled;
        self
    }

    /// Custom token prefix; empty string is rejected at build time.
    /// 自定义 token 前缀；空字符串在构建时拒绝。
    pub fn token_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config.token_prefix = Some(prefix.into());
        self
    }

    /// Opt-in cookie write for handlers using `write_token_cookie` (default false).
    /// Handler 调用 `write_token_cookie` 时是否真正写入 Cookie（默认 false）。
    pub fn is_write_cookie(mut self, write: bool) -> Self {
        self.config.cookie.is_write_cookie = write;
        self
    }

    /// Cookie Domain attribute.
    /// Cookie 的 Domain 属性。
    pub fn cookie_domain(mut self, domain: impl Into<String>) -> Self {
        self.config.cookie.domain = Some(domain.into());
        self
    }

    /// Cookie Path attribute.
    /// Cookie 的 Path 属性。
    pub fn cookie_path(mut self, path: impl Into<String>) -> Self {
        self.config.cookie.path = Some(path.into());
        self
    }

    /// Cookie HttpOnly flag.
    /// Cookie 的 HttpOnly 标志。
    pub fn cookie_http_only(mut self, http_only: bool) -> Self {
        self.config.cookie.http_only = http_only;
        self
    }

    /// Cookie Secure flag.
    /// Cookie 的 Secure 标志。
    pub fn cookie_secure(mut self, secure: bool) -> Self {
        self.config.cookie.secure = secure;
        self
    }

    /// Cookie SameSite attribute.
    /// Cookie 的 SameSite 属性。
    pub fn cookie_same_site(mut self, same_site: sa_token_adapter::context::SameSite) -> Self {
        self.config.cookie.same_site = Some(same_site);
        self
    }

    /// 设置存储键前缀（默认 `"sa:"`）。
    /// 此前缀用于 Redis / 数据库等存储后端的键命名。
    ///
    /// Set the storage key prefix (default `"sa:"`).
    /// Used when naming keys in Redis/DB backends.
    pub fn storage_key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config.storage_key_prefix = prefix.into();
        self
    }

    /// 设置存储键布局（A3-1）| Set the storage key layout (A3-1)
    pub fn key_layout(mut self, layout: SaKeyLayout) -> Self {
        self.config.key_layout = layout;
        self
    }

    /// 设置 JWT 密钥 | Set the JWT secret key
    pub fn jwt_secret_key(mut self, key: impl Into<String>) -> Self {
        self.config.jwt_secret_key = Some(key.into());
        self
    }

    /// 设置 JWT 算法 | Set the JWT algorithm
    pub fn jwt_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.config.jwt_algorithm = Some(algorithm.into());
        self
    }

    /// 设置 JWT 签发者 | Set the JWT issuer
    pub fn jwt_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.config.jwt_issuer = Some(issuer.into());
        self
    }

    /// 设置 JWT 受众 | Set the JWT audience
    pub fn jwt_audience(mut self, audience: impl Into<String>) -> Self {
        self.config.jwt_audience = Some(audience.into());
        self
    }

    /// 设置 JWT 失败时是否回退 UUID | Enable or disable UUID fallback on JWT failure
    pub fn jwt_fallback_on_error(mut self, fallback: bool) -> Self {
        self.config.jwt_fallback_on_error = fallback;
        self
    }

    /// 启用防重放攻击（nonce 机制）| Enable anti-replay protection via nonce
    pub fn enable_nonce(mut self, enable: bool) -> Self {
        self.config.enable_nonce = enable;
        self
    }

    /// 设置 Nonce 有效期（秒）| Set the nonce lifetime in seconds
    pub fn nonce_timeout(mut self, timeout: i64) -> Self {
        self.config.nonce_timeout = timeout;
        self
    }

    /// 启用 Refresh Token | Enable refresh tokens
    pub fn enable_refresh_token(mut self, enable: bool) -> Self {
        self.config.enable_refresh_token = enable;
        self
    }

    /// 设置 Refresh Token 有效期（秒）| Set the refresh-token lifetime in seconds
    pub fn refresh_token_timeout(mut self, timeout: i64) -> Self {
        self.config.refresh_token_timeout = timeout;
        self
    }

    /// 设置同一账号最大登录数量 | Set max concurrent logins per account
    pub fn max_login_count(mut self, count: i64) -> Self {
        self.config.max_login_count = count;
        self
    }

    /// 设置超出最大登录数时的下线模式 | Set the overflow logout mode
    pub fn overflow_logout_mode(mut self, mode: LogoutMode) -> Self {
        self.config.overflow_logout_mode = mode;
        self
    }

    /// 设置非并发顶号退出策略 | Set the non-concurrent replace exit mode
    pub fn replaced_login_exit_mode(mut self, mode: ReplacedLoginExitMode) -> Self {
        self.config.replaced_login_exit_mode = mode;
        self
    }

    /// 设置顶号范围 | Set the replace scope
    pub fn replaced_range(mut self, range: ReplacedRange) -> Self {
        self.config.replaced_range = range;
        self
    }

    /// 设置登录时是否立即创建 Token-Session
    /// Enable or disable creating a Token-Session immediately on login
    pub fn right_now_create_token_session(mut self, enabled: bool) -> Self {
        self.config.right_now_create_token_session = enabled;
        self
    }

    /// 设置获取 Token-Session 时是否校验登录态
    /// Enable or disable login check when fetching a Token-Session
    pub fn token_session_check_login(mut self, enabled: bool) -> Self {
        self.config.token_session_check_login = enabled;
        self
    }

    /// 设置默认 logout 范围 | Set the default logout range
    pub fn logout_range(mut self, range: LogoutRange) -> Self {
        self.config.logout_range = range;
        self
    }

    /// 设置 logout 时是否保留 Token-Session
    /// Enable or disable keeping the Token-Session on logout
    pub fn is_logout_keep_token_session(mut self, keep: bool) -> Self {
        self.config.is_logout_keep_token_session = keep;
        self
    }

    /// 设置权限/角色缓存 TTL（秒）。`<= 0` 关闭缓存。
    /// Sets the permission/role cache TTL in seconds; `<= 0` disables it.
    pub fn grant_cache_ttl(mut self, seconds: i64) -> Self {
        self.config.grant_cache_ttl = seconds;
        self
    }

    /// 设置缓存条目上限（跨全部分片的总量）。
    /// Sets the total cache capacity across all shards.
    pub fn grant_cache_max_entries(mut self, max: usize) -> Self {
        self.config.grant_cache_max_entries = max;
        self
    }

    /// 开关单飞（并发未命中合并为一次底层加载）。
    /// Toggles single-flight loading for concurrent cache misses.
    pub fn grant_cache_single_flight(mut self, enabled: bool) -> Self {
        self.config.grant_cache_single_flight = enabled;
        self
    }

    /// 开关请求级授权快照。
    /// Toggles the per-request authorization snapshot.
    pub fn grant_request_scope(mut self, enabled: bool) -> Self {
        self.config.grant_request_scope = enabled;
        self
    }

    /// 设置只读 `StpInterface` 下的写策略。
    /// Sets the write policy used with a read-only `StpInterface`.
    pub fn grant_write_policy(mut self, policy: GrantWritePolicy) -> Self {
        self.config.grant_write_policy = policy;
        self
    }

    /// Toggle role wildcard matching (default: exact).
    /// 开关角色通配符匹配（默认精确匹配）。
    pub fn role_wildcard(mut self, enabled: bool) -> Self {
        self.config.role_wildcard = enabled;
        self
    }

    /// 设置 `context_auto_create`
    /// Set whether `with_current_mut` should auto-create an empty context.
    pub fn context_auto_create(mut self, enable: bool) -> Self {
        self.config.context_auto_create = enable;
        self
    }

    /// HTTP Basic account (`user:password`)
    /// HTTP Basic 账号（`user:password`）
    pub fn http_basic(mut self, account: impl Into<String>) -> Self {
        self.config.http_basic = account.into();
        self
    }

    /// Same-Token TTL in seconds
    /// Same-Token 有效期（秒）
    pub fn same_token_timeout(mut self, timeout: i64) -> Self {
        self.config.same_token_timeout = timeout;
        self
    }

    /// Same-Token header name
    /// Same-Token 请求头名
    pub fn same_token_header(mut self, name: impl Into<String>) -> Self {
        self.config.same_token_header = name.into();
        self
    }

    /// Max attempts when allocating a unique login / temp token (`-1` = no retry).
    /// 分配唯一登录/临时 token 的最大尝试次数（`-1` 表示不重试）。
    pub fn max_try_times(mut self, n: i32) -> Self {
        self.config.max_try_times = n;
        self
    }

    /// HMAC secret for `RequestSign` via StpUtil (independent from JWT).
    /// StpUtil 使用的 HMAC 密钥（与 JWT 密钥分离）。
    pub fn sign_secret_key(mut self, key: impl Into<String>) -> Self {
        self.config.sign_secret_key = Some(key.into());
        self
    }

    /// Timestamp window in seconds for `RequestSign`.
    /// `RequestSign` 的时间窗（秒）。
    pub fn sign_window_secs(mut self, secs: i64) -> Self {
        self.config.sign_window_secs = secs;
        self
    }

    /// 设置存储层序列化器（默认 JSON）
    /// Set the storage serializer (JSON by default)
    pub fn serializer(mut self, serializer: SharedSerializer) -> Self {
        self.serializer = Some(serializer);
        self
    }

    /// 设置存储适配器 | Set the storage adapter
    pub fn storage(mut self, storage: Arc<dyn SaStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// 注入共享事件总线；未设置时 Manager::new 内部创建默认 bus
    ///
    /// Injects a shared event bus; if not set, Manager::new creates a default bus internally.
    pub fn event_bus(mut self, bus: SaTokenEventBus) -> Self {
        self.event_bus = Some(bus);
        self
    }

    /// 注册事件监听器（可多次调用以注册多个）。
    /// Register an event listener (call multiple times for multiple listeners).
    ///
    /// # 示例 | Example
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use sa_token_core::{SaTokenConfig, SaTokenListener};
    ///
    /// struct MyListener;
    /// impl SaTokenListener for MyListener { /* ... */ }
    ///
    /// let manager = SaTokenConfig::builder()
    ///     .storage(Arc::new(MemoryStorage::new()))
    ///     .register_listener(Arc::new(MyListener))
    ///     .build();
    /// ```
    pub fn register_listener(mut self, listener: Arc<dyn SaTokenListener>) -> Self {
        self.listeners.push(listener);
        self
    }

    /// 构建 `SaTokenManager`（需先设置 `storage`）。
    ///
    /// 自动完成：
    /// 1. 创建 `SaTokenManager`
    /// 2. 注册所有事件监听器
    /// 3. 初始化 `StpUtil`
    ///
    /// Build a `SaTokenManager` (`storage` must be set first).
    ///
    /// Automatically:
    /// 1. Creates `SaTokenManager`
    /// 2. Registers all event listeners
    /// 3. Initializes `StpUtil`
    ///
    /// # Panics
    /// 未设置 `storage` 时 panic。
    /// Panics if `storage` was not set.
    ///
    /// # 示例 | Example
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use sa_token_core::SaTokenConfig;
    /// use sa_token_storage_memory::MemoryStorage;
    ///
    /// // 一行完成初始化 | Complete initialization in one line
    /// SaTokenConfig::builder()
    ///     .storage(Arc::new(MemoryStorage::new()))
    ///     .timeout(7200)
    ///     .register_listener(Arc::new(MyListener))
    ///     .build();
    /// ```
    #[allow(clippy::panic)]
    pub fn build(self) -> crate::SaTokenManager {
        self.try_build()
            .unwrap_or_else(|e| panic!("SaTokenConfigBuilder::build failed: {e}"))
    }

    /// Build Manager; JWT misconfig returns Err instead of panicking later.
    /// 构造 Manager；JWT 配错在此处返回 Err，而不是延后 panic。
    pub fn try_build(self) -> SaTokenResult<crate::SaTokenManager> {
        let manager = self.try_build_manager_only()?;
        if let Err(SaTokenError::AlreadyInitialized) =
            crate::StpUtil::try_init_manager(manager.clone())
        {
            tracing::warn!(
                "StpUtil already initialized; returning Manager without replacing global instance"
            );
        }
        Ok(manager)
    }

    /// 仅构造 Manager：注册监听器 / 注入 EventBus，**不**写入全局 StpUtil。
    /// Construct Manager only: listeners + event bus; do **not** touch global StpUtil.
    #[allow(clippy::panic)]
    pub fn build_manager_only(self) -> crate::SaTokenManager {
        self.try_build_manager_only()
            .unwrap_or_else(|e| panic!("SaTokenConfigBuilder::build_manager_only failed: {e}"))
    }

    fn try_build_manager_only(self) -> SaTokenResult<crate::SaTokenManager> {
        let mut config = self.config;
        if let Some(serializer) = self.serializer {
            config.serializer = serializer;
        }
        config.validate_jwt()?;
        config.validate_token_io()?;
        let storage = self.storage.ok_or_else(|| {
            SaTokenError::ConfigError("Storage must be set before building SaTokenManager".into())
        })?;
        let mut manager = crate::SaTokenManager::new(storage, config);

        if let Some(bus) = self.event_bus {
            manager = manager.with_event_bus(bus);
        }

        if !self.listeners.is_empty() {
            let event_bus = manager.event_bus();
            for listener in self.listeners {
                event_bus.register(listener);
            }
        }

        Ok(manager)
    }

    /// 仅构建配置（不创建 Manager）
    /// Build the config only (without creating a Manager)
    #[allow(clippy::panic)]
    pub fn build_config(self) -> SaTokenConfig {
        self.try_build_config()
            .unwrap_or_else(|e| panic!("SaTokenConfigBuilder::build_config failed: {e}"))
    }

    /// Build config after JWT validation (does not construct Manager).
    /// 校验 JWT 后只构建配置（不构造 Manager）。
    pub fn try_build_config(self) -> SaTokenResult<SaTokenConfig> {
        let mut config = self.config;
        if let Some(serializer) = self.serializer {
            config.serializer = serializer;
        }
        config.validate_jwt()?;
        Ok(config)
    }
}
