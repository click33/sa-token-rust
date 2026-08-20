// Author: 金书记 | Author: Jin Shuji
//
//! Unified Storage Key Construction | 存储键统一构造（P3）
//!
//! Single source of truth for **all** sa-token storage keys.
//! sa-token **全部**存储键的唯一来源。
//!
//! ## Why This Module Exists | 本模块存在的理由
//!
//! Before this module, storage keys were built via ad-hoc `format!` calls scattered
//! across 10+ files. Any prefix/layout change required touching every call site,
//! and a single typo caused silent data isolation bugs (e.g. `login_type="admin"`
//! writing to one key but reading from another).
//! 在本模块之前，存储键由散落在 10+ 个文件中的临时 `format!` 拼接而成。
//! 任何前缀/布局变更都需改动所有调用点，一个拼写错误就会造成静默的数据隔离 bug
//! （例如 `login_type="admin"` 写入一个键、读取另一个键）。
//!
//! ## Two Layouts | 两种布局
//!
//! | Layout | Format | Purpose |
//! |--------|--------|---------|
//! | [`SaKeyLayout::ThreeSegment`] | `{prefix}{category}:{account_ns}` | Rust default, zero migration for existing data \| Rust 默认，存量数据零迁移 |
//! | [`SaKeyLayout::JavaFourSegment`] | `{token_name}:{login_type}:{category}:{id}` | Four-segment layout for sharing a keyspace with another service. / 四段布局，便于与另一套服务共用键空间。 |
//!
//! ## Key Categories | 键分类
//!
//! ```text
//! Global keys (token is globally unique, no account isolation needed)
//! 全局键（token 全局唯一，无需账号体系隔离）
//!   token_info / token_id_mapping / token_session / last_active / nonce / refresh
//!
//! Account-scoped keys (must be isolated per login_type)
//! 账号域键（必须按 login_type 隔离）
//!   login_token / login_token_index / account_session / permission / role
//!   disable / refresh_user_index
//! ```
//!
//! ## Type Safety: LoginId vs AccountNs (A3-2) | 类型安全：LoginId 与 AccountNs（A3-2）
//!
//! A historic bug class: callers computed `account_ns()` first, then passed the
//! **already-namespaced** string into an API expecting a **raw** login_id, causing
//! double namespacing under `JavaFourSegment`. The [`LoginId`] / [`AccountNs`]
//! newtypes make this a **compile error** instead of a runtime data bug.
//! 一类历史 bug：调用方先算出 `account_ns()`，再把**已命名空间化**的字符串传给期望
//! **裸** login_id 的 API，在 `JavaFourSegment` 下造成双重命名空间化。
//! [`LoginId`] / [`AccountNs`] newtype 将其从运行时数据 bug 变为**编译错误**。
//!
//! ## Performance Notes (A3-14, A3-15) | 性能说明（A3-14、A3-15）
//!
//! - `root: Arc<str>` — cloning [`SaKeys`] is a refcount bump, not a heap copy.
//!   `root: Arc<str>` — 克隆 [`SaKeys`] 是引用计数递增，而非堆拷贝。
//! - Key building uses `String::with_capacity` + `write!` — **one** allocation per key.
//!   键构造使用 `String::with_capacity` + `write!` — 每个键**一次**分配。

use std::fmt::Write as _;
use std::sync::Arc;

use crate::config::SaTokenConfig;

// ==================== Login Type Constants (A3-13) | 账号体系常量（A3-13） ====================

/// Default login type in Rust sa-token | Rust sa-token 中的默认账号体系
///
/// Normalized to a bare `login_id` by [`SaKeys::account_ns`] for backward compatibility.
/// 由 [`SaKeys::account_ns`] 归一为裸 `login_id`，以保持向后兼容。
pub const LOGIN_TYPE_DEFAULT: &str = "default";

/// Canonical default account-system id `login`, stored as a bare login_id.
/// 默认账号体系 id `login`，键中为裸 login_id。
///
/// Also normalized to a bare `login_id`, so `"default"` and `"login"`
/// produce identical three-segment keys.
/// 同样归一为裸 `login_id`，因此 `"default"` 与 `"login"`
/// 在三段式下产出完全相同的键。
pub const LOGIN_TYPE_LOGIN: &str = "login";

/// Login type used by the SSO server side | SSO 服务端使用的账号体系
pub const LOGIN_TYPE_SSO: &str = "sso";

/// Login type used by the SSO client side | SSO 客户端使用的账号体系
pub const LOGIN_TYPE_SSO_CLIENT: &str = "sso_client";

/// Escape sequence for a literal `:` inside a `login_id` (A3-16)
/// `login_id` 内字面量 `:` 的转义序列（A3-16）
const COLON_ESCAPE: &str = "%3A";

/// Maximum accepted `login_id` byte length | 可接受的 `login_id` 最大字节长度
const MAX_LOGIN_ID_LEN: usize = 512;

// ==================== Key Error | 键构造错误 ====================

/// Storage key construction error | 存储键构造错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// `login_id` is empty | `login_id` 为空
    EmptyLoginId,

    /// `login_id` exceeds [`MAX_LOGIN_ID_LEN`] bytes | `login_id` 超过 [`MAX_LOGIN_ID_LEN`] 字节
    LoginIdTooLong {
        /// Actual byte length | 实际字节长度
        actual: usize,
        /// Maximum allowed byte length | 允许的最大字节长度
        max: usize,
    },

    /// A namespaced-id API was called under a layout that cannot support it
    /// 在无法支持的布局下调用了「已命名空间化 id」API
    NamespacedIdUnsupportedByLayout {
        /// The API that was called | 被调用的 API 名
        api: &'static str,
    },
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyLoginId => write!(f, "login_id must not be empty"),
            Self::LoginIdTooLong { actual, max } => write!(
                f,
                "login_id is too long: {actual} bytes exceeds the maximum of {max} bytes"
            ),
            Self::NamespacedIdUnsupportedByLayout { api } => write!(
                f,
                "{api} requires SaKeyLayout::ThreeSegment; use the (login_type, login_id) variant instead"
            ),
        }
    }
}

impl std::error::Error for KeyError {}

// ==================== LoginId / AccountNs Newtypes (A3-2) ====================

/// A **raw** account identifier, not yet namespaced | **裸**账号标识符，尚未命名空间化
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct LoginId(String);

impl LoginId {
    /// Wraps a raw account id without validation | 包装裸账号 id，不做校验
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Wraps a raw account id, rejecting empty / over-long values (A3-16)
    /// 包装裸账号 id，拒绝空值/超长值（A3-16）
    pub fn try_new(id: impl Into<String>) -> Result<Self, KeyError> {
        let id = id.into();
        SaKeys::validate_login_id(&id)?;
        Ok(Self(id))
    }

    /// Borrows the underlying raw id | 借用底层裸 id
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unwraps into the owned `String` | 解包为拥有所有权的 `String`
    #[inline]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for LoginId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for LoginId {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<&str> for LoginId {
    #[inline]
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for LoginId {
    #[inline]
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// An **already-namespaced** account identifier | **已命名空间化**的账号标识符
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct AccountNs(String);

impl AccountNs {
    /// Wraps a value that is **known** to be already namespaced
    /// 包装一个**已知**已命名空间化的值
    #[inline]
    pub fn from_trusted(ns: impl Into<String>) -> Self {
        Self(ns.into())
    }

    /// Borrows the underlying namespaced id | 借用底层已命名空间化的 id
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unwraps into the owned `String` | 解包为拥有所有权的 `String`
    #[inline]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for AccountNs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for AccountNs {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ==================== Key Layout | 键布局策略 ====================

/// Storage key layout strategy | 存储键布局策略
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum SaKeyLayout {
    /// Three-segment layout (Rust default) | 三段式布局（Rust 默认）
    ///
    /// Format: `{storage_key_prefix}{category}:{account_ns}`
    /// 格式：`{storage_key_prefix}{category}:{account_ns}`
    #[default]
    ThreeSegment,

    /// Four-segment layout | 四段式布局
    ///
    /// Format: `{token_name}:{login_type}:{category}:{login_id}`
    /// 格式：`{token_name}:{login_type}:{category}:{login_id}`
    JavaFourSegment,
}

// ==================== SaKeys | 键构造器 ====================

/// Storage key builder — the single source of truth for key schema
/// 存储键构造器 —— 键 schema 的唯一来源
#[derive(Debug, Clone)]
pub struct SaKeys {
    /// Key root | 键根
    root: Arc<str>,
    /// Active layout strategy | 生效的布局策略
    layout: SaKeyLayout,
    /// ThreeSegment 下 `"{root}token:"`，避免 scan 解析重复分配。
    /// Cached `"{root}token:"` for ThreeSegment scan parsing.
    token_colon: Arc<str>,
}

impl SaKeys {
    /// Creates a builder with the default [`SaKeyLayout::ThreeSegment`] layout
    /// 使用默认 [`SaKeyLayout::ThreeSegment`] 布局创建构造器
    pub fn new(prefix: impl AsRef<str>) -> Self {
        let root: Arc<str> = Arc::from(prefix.as_ref());
        let token_colon = Arc::from(format!("{root}token:"));
        Self {
            root,
            layout: SaKeyLayout::ThreeSegment,
            token_colon,
        }
    }

    /// Creates a builder with an explicit layout | 使用显式布局创建构造器
    pub fn with_layout(root: impl AsRef<str>, layout: SaKeyLayout) -> Self {
        let root: Arc<str> = match layout {
            SaKeyLayout::ThreeSegment => Arc::from(root.as_ref()),
            SaKeyLayout::JavaFourSegment => Arc::from(root.as_ref().trim_end_matches(':')),
        };
        let token_colon = Arc::from(format!("{root}token:"));
        Self {
            root,
            layout,
            token_colon,
        }
    }

    /// Builds from config, honouring `key_layout` (A3-1) | 从配置构建，遵循 `key_layout`（A3-1）
    pub fn from_config(config: &SaTokenConfig) -> Self {
        match config.key_layout {
            SaKeyLayout::ThreeSegment => {
                Self::with_layout(&config.storage_key_prefix, SaKeyLayout::ThreeSegment)
            }
            SaKeyLayout::JavaFourSegment => {
                Self::with_layout(&config.token_name, SaKeyLayout::JavaFourSegment)
            }
        }
    }

    /// Returns the key root | 返回键根
    #[inline]
    pub fn prefix(&self) -> &str {
        &self.root
    }

    /// Returns the active layout | 返回生效的布局
    #[inline]
    pub fn layout(&self) -> SaKeyLayout {
        self.layout
    }

    #[inline]
    fn is_java(&self) -> bool {
        matches!(self.layout, SaKeyLayout::JavaFourSegment)
    }

    /// Normalizes `(login_type, login_id)` into a single key segment (A3-2, A3-16)
    /// 将 `(login_type, login_id)` 归一为单个键段（A3-2、A3-16）
    pub fn account_ns(login_type: &str, login_id: &LoginId) -> AccountNs {
        let id = login_id.as_str();

        if Self::is_default_login_type(login_type) {
            return AccountNs(id.to_string());
        }

        let needs_escape = id.contains(':');
        let escaped_extra = if needs_escape {
            id.matches(':').count() * (COLON_ESCAPE.len() - 1)
        } else {
            0
        };

        let mut out = String::with_capacity(login_type.len() + 1 + id.len() + escaped_extra);
        out.push_str(login_type);
        out.push(':');
        if needs_escape {
            Self::push_escaped(&mut out, id);
        } else {
            out.push_str(id);
        }
        AccountNs(out)
    }

    /// Returns `true` for login types normalized to the bare id
    /// 对归一为裸 id 的账号体系返回 `true`
    #[inline]
    pub fn is_default_login_type(login_type: &str) -> bool {
        login_type.is_empty() || login_type == LOGIN_TYPE_DEFAULT || login_type == LOGIN_TYPE_LOGIN
    }

    #[inline]
    fn push_escaped(out: &mut String, src: &str) {
        for ch in src.chars() {
            if ch == ':' {
                out.push_str(COLON_ESCAPE);
            } else {
                out.push(ch);
            }
        }
    }

    /// Validates a `login_id` before it is used in a key (A3-16)
    /// 在 `login_id` 用于构造键之前校验它（A3-16）
    pub fn validate_login_id(login_id: &str) -> Result<(), KeyError> {
        if login_id.is_empty() {
            return Err(KeyError::EmptyLoginId);
        }
        if login_id.len() > MAX_LOGIN_ID_LEN {
            return Err(KeyError::LoginIdTooLong {
                actual: login_id.len(),
                max: MAX_LOGIN_ID_LEN,
            });
        }
        Ok(())
    }

    fn build_global(&self, category: &str, id: &str, login_type: Option<&str>) -> String {
        match self.layout {
            SaKeyLayout::ThreeSegment => {
                let mut out =
                    String::with_capacity(self.root.len() + category.len() + 1 + id.len());
                out.push_str(&self.root);
                out.push_str(category);
                out.push(':');
                out.push_str(id);
                out
            }
            SaKeyLayout::JavaFourSegment => {
                let lt = login_type.unwrap_or(LOGIN_TYPE_LOGIN);
                let mut out = String::with_capacity(
                    self.root.len() + 1 + lt.len() + 1 + category.len() + 1 + id.len(),
                );
                let _ = write!(out, "{}:{}:{}:{}", self.root, lt, category, id);
                out
            }
        }
    }

    fn build_account(&self, category: &str, login_type: &str, login_id: &str) -> String {
        match self.layout {
            SaKeyLayout::ThreeSegment => {
                if Self::is_default_login_type(login_type) {
                    let mut out = String::with_capacity(
                        self.root.len() + category.len() + 1 + login_id.len(),
                    );
                    out.push_str(&self.root);
                    out.push_str(category);
                    out.push(':');
                    out.push_str(login_id);
                    return out;
                }

                let escaped_extra = login_id.matches(':').count() * (COLON_ESCAPE.len() - 1);
                let mut out = String::with_capacity(
                    self.root.len()
                        + category.len()
                        + 1
                        + login_type.len()
                        + 1
                        + login_id.len()
                        + escaped_extra,
                );
                out.push_str(&self.root);
                out.push_str(category);
                out.push(':');
                out.push_str(login_type);
                out.push(':');
                Self::push_escaped(&mut out, login_id);
                out
            }
            SaKeyLayout::JavaFourSegment => {
                let lt = if login_type.is_empty() {
                    LOGIN_TYPE_LOGIN
                } else {
                    login_type
                };
                let mut out = String::with_capacity(
                    self.root.len() + 1 + lt.len() + 1 + category.len() + 1 + login_id.len(),
                );
                let _ = write!(out, "{}:{}:{}:{}", self.root, lt, category, login_id);
                out
            }
        }
    }

    fn build_from_ns(
        &self,
        category: &str,
        ns: &AccountNs,
        api: &'static str,
    ) -> Result<String, KeyError> {
        if self.is_java() {
            return Err(KeyError::NamespacedIdUnsupportedByLayout { api });
        }
        Ok(self.build_global(category, ns.as_str(), None))
    }

    /// Deprecated escape hatch kept for legacy call sites (A3-10)
    /// 为存量调用点保留的已弃用逃生舱（A3-10）
    #[deprecated(
        since = "0.1.19",
        note = "Use a named key method (token_info / login_token / ...) so the key layout is respected"
    )]
    pub fn make_key(&self, suffix: &str, id: &str) -> String {
        let mut out = String::with_capacity(self.root.len() + suffix.len() + id.len());
        out.push_str(&self.root);
        out.push_str(suffix);
        out.push_str(id);
        out
    }

    // ==================== Token Global Keys | Token 全局键 ====================

    /// Token → login_id mapping key | Token → login_id 映射键
    #[inline]
    pub fn token_info(&self, token: &str) -> String {
        self.build_global("token", token, None)
    }

    /// Token key for a specific account system (A3-4) | 指定账号体系的 Token 键（A3-4）
    #[inline]
    pub fn token_info_with_type(&self, login_type: &str, token: &str) -> String {
        self.build_global("token", token, Some(login_type))
    }

    /// Reverse token → id mapping key (Rust-specific) | 反向 token → id 映射键（Rust 独有）
    #[inline]
    pub fn token_id_mapping(&self, token: &str) -> String {
        self.build_global("token-id", token, None)
    }

    /// Token-Session key | Token-Session 键
    #[inline]
    pub fn token_session(&self, token: &str) -> String {
        self.build_global("token-session", token, None)
    }

    /// Token-Session key for a specific account system (A3-4)
    /// 指定账号体系的 Token-Session 键（A3-4）
    #[inline]
    pub fn token_session_with_type(&self, login_type: &str, token: &str) -> String {
        self.build_global("token-session", token, Some(login_type))
    }

    /// Last-active timestamp key | 最后活跃时间键
    #[inline]
    pub fn last_active(&self, token: &str) -> String {
        self.build_global("last-active", token, None)
    }

    /// Last-active key for a specific account system (A3-4)
    /// 指定账号体系的最后活跃时间键（A3-4）
    #[inline]
    pub fn last_active_with_type(&self, login_type: &str, token: &str) -> String {
        self.build_global("last-active", token, Some(login_type))
    }

    // ==================== Account-Scoped Keys | 账号域键 ====================

    /// login_id → token mapping key (Rust-specific) | login_id → token 映射键（Rust 独有）
    #[inline]
    pub fn login_token(&self, login_type: &str, login_id: &str) -> String {
        self.build_account("login:token", login_type, login_id)
    }

    /// Multi-device token index key (Rust-specific) | 多设备 token 索引键（Rust 独有）
    #[inline]
    pub fn login_token_index(&self, login_type: &str, login_id: &str) -> String {
        self.build_account("login:tokens", login_type, login_id)
    }

    /// Account-Session key | Account-Session 键
    #[inline]
    pub fn account_session(&self, login_type: &str, login_id: &str) -> String {
        self.build_account("session", login_type, login_id)
    }

    /// Account-Session key from an already-namespaced id (A3-2)
    /// 从已命名空间化 id 构造 Account-Session 键（A3-2）
    #[inline]
    pub fn session_by_ns(&self, ns: &AccountNs) -> Result<String, KeyError> {
        self.build_from_ns("session", ns, "SaKeys::session_by_ns")
    }

    /// Permission list key | 权限列表键
    #[inline]
    pub fn permission(&self, login_type: &str, login_id: &str) -> String {
        self.build_account("permission", login_type, login_id)
    }

    /// Role list key | 角色列表键
    #[inline]
    pub fn role(&self, login_type: &str, login_id: &str) -> String {
        self.build_account("role", login_type, login_id)
    }

    /// Account ban (disable) key | 账号封禁键
    pub fn disable(&self, login_type: &str, login_id: &str, service: &str) -> String {
        match self.layout {
            SaKeyLayout::ThreeSegment => {
                let mut out = self.build_account("disable", login_type, login_id);
                out.push(':');
                out.push_str(service);
                out
            }
            SaKeyLayout::JavaFourSegment => {
                let lt = if login_type.is_empty() {
                    LOGIN_TYPE_LOGIN
                } else {
                    login_type
                };
                let mut out = String::with_capacity(
                    self.root.len() + 1 + lt.len() + 9 + service.len() + 1 + login_id.len(),
                );
                let _ = write!(out, "{}:{}:disable:{}:{}", self.root, lt, service, login_id);
                out
            }
        }
    }

    /// Ban key from an already-namespaced id (A3-2) | 从已命名空间化 id 构造封禁键（A3-2）
    pub fn disable_by_ns(&self, ns: &AccountNs, service: &str) -> Result<String, KeyError> {
        if self.is_java() {
            return Err(KeyError::NamespacedIdUnsupportedByLayout {
                api: "SaKeys::disable_by_ns",
            });
        }
        let mut out = self.build_global("disable", ns.as_str(), None);
        out.push(':');
        out.push_str(service);
        Ok(out)
    }

    /// Second-factor (safe) verification key | 二级认证键
    pub fn safe(&self, token: &str, service: &str) -> String {
        self.safe_with_type(LOGIN_TYPE_LOGIN, token, service)
    }

    /// Second-factor key for a specific account system | 指定账号体系的二级认证键
    pub fn safe_with_type(&self, login_type: &str, token: &str, service: &str) -> String {
        match self.layout {
            SaKeyLayout::ThreeSegment => {
                let mut out = self.build_global("safe", token, None);
                out.push(':');
                out.push_str(service);
                out
            }
            SaKeyLayout::JavaFourSegment => {
                let lt = if login_type.is_empty() {
                    LOGIN_TYPE_LOGIN
                } else {
                    login_type
                };
                let mut out = String::with_capacity(
                    self.root.len() + 1 + lt.len() + 6 + service.len() + 1 + token.len(),
                );
                let _ = write!(out, "{}:{}:safe:{}:{}", self.root, lt, service, token);
                out
            }
        }
    }

    // ==================== Nonce / Refresh / OAuth2 / SSO / Online / Distributed ====================

    /// Nonce replay-protection key | Nonce 防重放键
    #[inline]
    pub fn nonce(&self, nonce_value: &str) -> String {
        self.build_global("nonce", nonce_value, None)
    }

    /// Refresh token key | Refresh Token 键
    #[inline]
    pub fn refresh(&self, refresh_token: &str) -> String {
        self.build_global("refresh", refresh_token, None)
    }

    /// Per-account refresh token index key | 按账号的 Refresh Token 索引键
    #[inline]
    pub fn refresh_user_index(&self, login_type: &str, login_id: &str) -> String {
        self.build_account("refresh:user", login_type, login_id)
    }

    /// Refresh index key from an already-namespaced id (A3-2)
    /// 从已命名空间化 id 构造 Refresh 索引键（A3-2）
    #[inline]
    pub fn refresh_user_index_by_ns(&self, ns: &AccountNs) -> Result<String, KeyError> {
        self.build_from_ns("refresh:user", ns, "SaKeys::refresh_user_index_by_ns")
    }

    /// OAuth2 client registration key | OAuth2 客户端注册键
    #[inline]
    pub fn oauth2_client(&self, client_id: &str) -> String {
        self.build_global("oauth2:client", client_id, None)
    }

    /// OAuth2 authorization code key | OAuth2 授权码键
    #[inline]
    pub fn oauth2_code(&self, code: &str) -> String {
        self.build_global("oauth2:code", code, None)
    }

    /// OAuth2 access token key | OAuth2 访问令牌键
    #[inline]
    pub fn oauth2_token(&self, access_token: &str) -> String {
        self.build_global("oauth2:token", access_token, None)
    }

    /// OAuth2 refresh token key | OAuth2 刷新令牌键
    #[inline]
    pub fn oauth2_refresh(&self, refresh_token: &str) -> String {
        self.build_global("oauth2:refresh", refresh_token, None)
    }

    /// SSO ticket key | SSO 票据键
    #[inline]
    pub fn sso_ticket(&self, ticket_id: &str) -> String {
        self.build_global("sso:ticket", ticket_id, None)
    }

    /// SSO session key | SSO 会话键
    #[inline]
    pub fn sso_session(&self, login_id: &str) -> String {
        self.build_global("sso:session", login_id, None)
    }

    /// SSO login-token key | SSO 登录令牌键
    #[inline]
    pub fn sso_login_token(&self, login_type: &str, login_id: &str) -> String {
        self.login_token(login_type, login_id)
    }

    /// Online-user record key | 在线用户记录键
    #[inline]
    pub fn online(&self, login_id: &str, token: &str) -> String {
        let mut out = self.build_global("online", login_id, None);
        out.push(':');
        out.push_str(token);
        out
    }

    /// Online-user record key for a specific account system (A3-13)
    /// 指定账号体系的在线用户记录键（A3-13）
    #[inline]
    pub fn online_with_type(&self, login_type: &str, login_id: &str, token: &str) -> String {
        let mut out = self.build_account("online", login_type, login_id);
        out.push(':');
        out.push_str(token);
        out
    }

    /// Online-user index key | 在线用户索引键
    #[inline]
    pub fn online_index(&self, login_id: &str) -> String {
        self.build_global("online:index", login_id, None)
    }

    /// Online-user index key for a specific account system.
    /// 指定账号体系的在线用户索引键。
    #[inline]
    pub fn online_index_with_type(&self, login_type: &str, login_id: &str) -> String {
        self.build_account("online:index", login_type, login_id)
    }

    /// Global unique set of currently online login ids (list primitive).
    /// 当前在线账号 ID 的全局去重集合（走列表原语）。
    #[inline]
    pub fn online_users_set(&self) -> String {
        self.build_global("online", "users", None)
    }

    /// Distributed session key | 分布式会话键
    #[inline]
    pub fn distributed_session(&self, session_id: &str) -> String {
        self.build_global("dsession", session_id, None)
    }

    /// Distributed session index key | 分布式会话索引键
    #[inline]
    pub fn distributed_session_index(&self, login_id: &str) -> String {
        self.build_global("dsession:index", login_id, None)
    }

    /// Distributed service credential key | 分布式服务凭证键
    #[inline]
    pub fn distributed_service(&self, service_id: &str) -> String {
        self.build_global("dservice", service_id, None)
    }

    /// Current Same-Token storage key.
    /// 当前 Same-Token 存储键。
    #[inline]
    pub fn same_token(&self) -> String {
        self.build_global("var", "same-token", None)
    }

    /// Previous Same-Token storage key (grace window).
    /// 上一次 Same-Token 存储键（宽限期）。
    #[inline]
    pub fn same_token_past(&self) -> String {
        self.build_global("var", "same-token-past", None)
    }

    /// Request-sign nonce occupancy key (not the login nonce space).
    /// 请求签名 nonce 占位键（与登录 nonce 键空间分离）。
    #[inline]
    pub fn sign_nonce(&self, nonce: &str) -> String {
        self.build_global("sign-nonce", nonce, None)
    }

    /// Temp-token body key.
    /// 临时令牌体键。
    #[inline]
    pub fn temp_token(&self, namespace: &str, token: &str) -> String {
        let mut cat = String::from("temp-token:");
        cat.push_str(namespace);
        self.build_global(&cat, token, None)
    }

    /// Temp-token reverse index (digest of the string value).
    /// 临时令牌反查索引（字符串 value 的摘要）。
    #[inline]
    pub fn temp_index(&self, namespace: &str, value_digest: &str) -> String {
        let mut cat = String::from("temp-index:");
        cat.push_str(namespace);
        self.build_global(&cat, value_digest, None)
    }

    // ==================== Scan & Parse (A3-11, A3-12) | 扫描与解析（A3-11、A3-12） ====================

    /// Returns the key prefix for a category, layout-aware (A3-11)
    /// 返回某分类的键前缀，布局感知（A3-11）
    pub fn category_prefix(&self, category: &str, login_type: Option<&str>) -> String {
        match self.layout {
            SaKeyLayout::ThreeSegment => {
                let mut out = String::with_capacity(self.root.len() + category.len() + 1);
                out.push_str(&self.root);
                out.push_str(category);
                out.push(':');
                out
            }
            SaKeyLayout::JavaFourSegment => {
                let lt = login_type.unwrap_or(LOGIN_TYPE_LOGIN);
                let mut out =
                    String::with_capacity(self.root.len() + 1 + lt.len() + 1 + category.len() + 1);
                let _ = write!(out, "{}:{}:{}:", self.root, lt, category);
                out
            }
        }
    }

    /// Token key prefix, for scan-and-strip workflows (A3-11)
    /// Token 键前缀，用于「扫描后剥离」工作流（A3-11）
    #[inline]
    pub fn token_key_prefix(&self, login_type: Option<&str>) -> String {
        self.category_prefix("token", login_type)
    }

    /// Glob pattern matching every token key (A3-11) | 匹配所有 token 键的 glob 模式（A3-11）
    pub fn token_scan_pattern(&self, login_type: Option<&str>) -> String {
        let mut out = self.token_key_prefix(login_type);
        out.push('*');
        out
    }

    /// Glob pattern for any category (A3-11) | 任意分类的 glob 模式（A3-11）
    pub fn scan_pattern(&self, category: &str, login_type: Option<&str>) -> String {
        let mut out = self.category_prefix(category, login_type);
        out.push('*');
        out
    }

    /// Extracts the token value from a scanned token key (A3-12)
    /// 从扫描到的 token 键中提取 token 值（A3-12）
    pub fn parse_token_from_key<'k>(
        &self,
        key: &'k str,
        login_type: Option<&str>,
    ) -> Option<&'k str> {
        // ThreeSegment 默认体系走缓存前缀，避免每次分配。
        // Default ThreeSegment uses the cached prefix to avoid allocation.
        if matches!(self.layout, SaKeyLayout::ThreeSegment)
            && login_type.map(Self::is_default_login_type).unwrap_or(true)
        {
            return key.strip_prefix(self.token_colon.as_ref());
        }
        let prefix = self.token_key_prefix(login_type);
        key.strip_prefix(prefix.as_str())
    }

    /// Extracts the id segment from a scanned key of a given category (A3-12)
    /// 从扫描到的指定分类键中提取 id 段（A3-12）
    pub fn parse_id_from_key<'k>(
        &self,
        key: &'k str,
        category: &str,
        login_type: Option<&str>,
    ) -> Option<&'k str> {
        let prefix = self.category_prefix(category, login_type);
        key.strip_prefix(prefix.as_str())
    }
}

impl Default for SaKeys {
    fn default() -> Self {
        Self::new("sa:")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_make_key(prefix: &str, suffix: &str, id: &str) -> String {
        format!("{prefix}{suffix}{id}")
    }

    fn id(s: &str) -> LoginId {
        LoginId::new(s)
    }

    #[test]
    fn account_ns_default_unchanged() {
        assert_eq!(SaKeys::account_ns("default", &id("u1")).as_str(), "u1");
        assert_eq!(SaKeys::account_ns("login", &id("u1")).as_str(), "u1");
        assert_eq!(SaKeys::account_ns("", &id("u1")).as_str(), "u1");
        assert_eq!(SaKeys::account_ns("admin", &id("u1")).as_str(), "admin:u1");
    }

    #[test]
    fn account_ns_colon_escaping() {
        assert_eq!(SaKeys::account_ns("default", &id("a:b")).as_str(), "a:b");
        assert_eq!(
            SaKeys::account_ns("admin", &id("a:b")).as_str(),
            "admin:a%3Ab"
        );
        assert_ne!(
            SaKeys::account_ns("a", &id("b:c")).as_str(),
            SaKeys::account_ns("a:b", &id("c")).as_str()
        );
    }

    #[test]
    fn three_segment_matches_legacy_make_key() {
        let keys = SaKeys::new("sa:");
        let login_id = "user_1";
        let token = "abc123";

        assert_eq!(
            keys.token_info(token),
            legacy_make_key("sa:", "token:", token)
        );
        assert_eq!(
            keys.login_token("default", login_id),
            legacy_make_key("sa:", "login:token:", login_id)
        );
        assert_eq!(
            keys.login_token_index("default", login_id),
            legacy_make_key("sa:", "login:tokens:", login_id)
        );
        assert_eq!(
            keys.account_session("default", login_id),
            legacy_make_key("sa:", "session:", login_id)
        );
        assert_eq!(
            keys.permission("default", login_id),
            legacy_make_key("sa:", "permission:", login_id)
        );
        assert_eq!(
            keys.role("default", login_id),
            legacy_make_key("sa:", "role:", login_id)
        );
        assert_eq!(
            keys.token_id_mapping(token),
            legacy_make_key("sa:", "token-id:", token)
        );
        assert_eq!(
            keys.token_session(token),
            legacy_make_key("sa:", "token-session:", token)
        );
        assert_eq!(
            keys.disable("default", login_id, "login"),
            legacy_make_key("sa:", "disable:", &format!("{login_id}:login"))
        );
        assert_eq!(
            keys.safe(token, "pay"),
            legacy_make_key("sa:", "safe:", &format!("{token}:pay"))
        );
        assert_eq!(
            keys.nonce("nonce_1"),
            legacy_make_key("sa:", "nonce:", "nonce_1")
        );
        assert_eq!(
            keys.refresh("rt_1"),
            legacy_make_key("sa:", "refresh:", "rt_1")
        );
        assert_eq!(
            keys.refresh_user_index("default", login_id),
            legacy_make_key("sa:", "refresh:user:", login_id)
        );
    }

    #[test]
    fn three_segment_admin_account_keys() {
        let keys = SaKeys::new("sa:");
        assert_eq!(
            keys.login_token("admin", "10001"),
            "sa:login:token:admin:10001"
        );
        assert_eq!(
            keys.login_token_index("admin", "10001"),
            "sa:login:tokens:admin:10001"
        );
        assert_eq!(
            keys.account_session("admin", "10001"),
            "sa:session:admin:10001"
        );
    }

    #[test]
    fn session_by_ns_three_segment() {
        let keys = SaKeys::new("sa:");
        let ns = SaKeys::account_ns("admin", &id("10001"));
        assert_eq!(keys.session_by_ns(&ns).unwrap(), "sa:session:admin:10001");
    }

    #[test]
    fn custom_prefix_matches_legacy_make_key() {
        let keys = SaKeys::new("myapp:");
        assert_eq!(keys.token_info("t1"), "myapp:token:t1");
        assert_eq!(keys.login_token("default", "u1"), "myapp:login:token:u1");
    }

    #[test]
    fn java_four_segment_layout() {
        let keys = SaKeys::with_layout("satoken", SaKeyLayout::JavaFourSegment);
        assert_eq!(keys.token_info("abc"), "satoken:login:token:abc");
        assert_eq!(
            keys.token_info_with_type("admin", "abc"),
            "satoken:admin:token:abc"
        );
        assert_eq!(
            keys.login_token("admin", "u1"),
            "satoken:admin:login:token:u1"
        );
        assert_eq!(
            keys.account_session("admin", "u1"),
            "satoken:admin:session:u1"
        );
        assert_eq!(
            keys.disable("admin", "u1", "login"),
            "satoken:admin:disable:login:u1"
        );
        assert_eq!(keys.safe("tok", "pay"), "satoken:login:safe:pay:tok");
    }

    #[test]
    fn scan_and_parse_token() {
        let keys = SaKeys::new("sa:");
        assert_eq!(keys.token_scan_pattern(None), "sa:token:*");
        assert_eq!(
            keys.parse_token_from_key("sa:token:abc123", None),
            Some("abc123")
        );
        assert_eq!(keys.parse_token_from_key("sa:session:u1", None), None);

        let keys = SaKeys::with_layout("satoken", SaKeyLayout::JavaFourSegment);
        assert_eq!(
            keys.token_scan_pattern(Some("admin")),
            "satoken:admin:token:*"
        );
        assert_eq!(
            keys.parse_token_from_key("satoken:admin:token:xyz", Some("admin")),
            Some("xyz")
        );
    }

    #[test]
    fn from_config_uses_storage_prefix() {
        let config = SaTokenConfig::builder()
            .storage_key_prefix("app:")
            .build_config();
        let keys = SaKeys::from_config(&config);
        assert_eq!(keys.token_info("x"), "app:token:x");
    }
}
