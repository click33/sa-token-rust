// Author: 金书记
//
//! StpUtil — static façade over the process-wide `SaTokenManager`.
//! StpUtil —— 进程内全局 `SaTokenManager` 的静态门面。
//!
//! ```rust,ignore
//! use sa_token_core::StpUtil;
//!
//! StpUtil::try_init_manager(manager)?;
//! let token = StpUtil::login("user_123").await?;
//! ```

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::OnceLock;

use crate::context::SaTokenContext;
use crate::event::{SaTokenEventBus, SaTokenListener};
use crate::keys::LOGIN_TYPE_DEFAULT;
use crate::session::SaSession;
use crate::token::{TokenInfo, TokenValue};
use crate::{SaTokenError, SaTokenManager, SaTokenResult};

/// 全局 SaTokenManager 实例（标准库 OnceLock，Rust 1.70+）
static GLOBAL_MANAGER: OnceLock<Arc<SaTokenManager>> = OnceLock::new();

/// LoginId trait — 登录 ID 零拷贝优先。
/// LoginId trait — prefer zero-copy login ids.
pub trait LoginId {
    /// 借用或拥有登录 ID；`&str` / `String` 走 Borrowed。
    /// Borrow or own the login id; `&str` / `String` use Borrowed.
    fn as_login_id(&self) -> Cow<'_, str>;

    /// 兼容旧 API：总是得到 owned `String`。
    /// Legacy helper: always returns an owned `String`.
    fn to_login_id(&self) -> String {
        self.as_login_id().into_owned()
    }
}

impl LoginId for str {
    fn as_login_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(self)
    }
}

impl LoginId for String {
    fn as_login_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.as_str())
    }
}

impl LoginId for &String {
    fn as_login_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.as_str())
    }
}

impl LoginId for &str {
    fn as_login_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(*self)
    }
}

macro_rules! impl_login_id_display {
    ($($t:ty),*) => {$(
        impl LoginId for $t {
            fn as_login_id(&self) -> Cow<'_, str> {
                Cow::Owned(self.to_string())
            }
        }
    )*};
}
impl_login_id_display!(i32, i64, u32, u64, i16, u16, isize, usize);

/// Static helpers for login, logout, and authorization.
/// 登录、登出与鉴权的静态辅助方法。
pub struct StpUtil;

impl StpUtil {
    // ==================== 初始化 ====================

    /// 尝试初始化全局 Manager（应用启动调用一次）
    /// Try to initialize the global manager (call once at startup).
    ///
    /// 重复调用返回 `AlreadyInitialized`，**不 panic**。
    /// Duplicate calls return `AlreadyInitialized` without panicking.
    pub fn try_init_manager(manager: SaTokenManager) -> SaTokenResult<()> {
        GLOBAL_MANAGER
            .set(Arc::new(manager))
            .map_err(|_| SaTokenError::AlreadyInitialized)
    }

    /// 初始化全局 Manager（兼容旧 API；重复仍 panic）
    /// Initialize global manager (legacy; still panics on duplicate).
    ///
    /// # 示例
    /// ```rust,ignore
    /// let manager = SaTokenConfig::builder()
    ///     .storage(Arc::new(MemoryStorage::new()))
    ///     .build();
    /// StpUtil::init_manager(manager);
    /// ```
    #[deprecated(note = "use try_init_manager() which returns Result instead of panicking")]
    #[allow(clippy::panic)]
    pub fn init_manager(manager: SaTokenManager) {
        Self::try_init_manager(manager).unwrap_or_else(|e| {
            panic!("{e}");
        });
    }

    /// 尝试获取全局 Manager
    /// Try to get the global manager
    pub fn try_get_manager() -> SaTokenResult<&'static Arc<SaTokenManager>> {
        GLOBAL_MANAGER.get().ok_or(SaTokenError::NotInitialized)
    }

    /// 获取全局 Manager（未初始化时 panic；仅内部兼容，优先 `try_get_manager`）
    /// Get the global manager (panics if missing; prefer `try_get_manager`).
    #[track_caller]
    #[allow(dead_code, clippy::panic)]
    pub(crate) fn get_manager() -> &'static Arc<SaTokenManager> {
        Self::try_get_manager().unwrap_or_else(|e| {
            panic!("{e}. Call StpUtil::try_init_manager() first.");
        })
    }

    /// 尝试获取全局配置（Manager 初始化前返回 None）
    ///
    /// Try to get global config; returns `None` before Manager initialization.
    pub(crate) fn try_get_config() -> Option<&'static crate::config::SaTokenConfig> {
        GLOBAL_MANAGER.get().map(|m| m.config.as_ref())
    }

    /// 解析「当前请求所属账号体系」（修 B2-23）。
    ///
    /// 顺序：请求上下文中的 token 元信息 → `default`。
    /// 无请求上下文时回落 `default`，保持旧行为。`Cow` 让常见分支零分配。
    ///
    /// Resolves the login type of the current request: token metadata in the
    /// request context first, then `default`. Falls back to `default` without a
    /// request context, preserving old behaviour. `Cow` keeps the common branch
    /// allocation-free.
    #[inline]
    fn resolve_login_type() -> Cow<'static, str> {
        match SaTokenContext::current_login_type() {
            Some(login_type) => Cow::Owned(login_type),
            None => Cow::Borrowed(LOGIN_TYPE_DEFAULT),
        }
    }

    /// 获取事件总线，用于注册监听器
    ///
    /// # 示例
    /// ```rust,ignore
    /// use sa_token_core::{StpUtil, SaTokenListener};
    /// use async_trait::async_trait;
    ///
    /// struct MyListener;
    ///
    /// #[async_trait]
    /// impl SaTokenListener for MyListener {
    ///     async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
    ///         println!("用户 {} 登录了", login_id);
    ///     }
    /// }
    ///
    /// // 注册监听器
    /// StpUtil::event_bus().register(Arc::new(MyListener));
    /// ```
    /// 尝试获取事件总线；未初始化返回 `None`（不 panic）。
    /// Try to get the event bus; `None` before init (no panic).
    pub fn event_bus() -> Option<&'static SaTokenEventBus> {
        GLOBAL_MANAGER.get().map(|m| &m.event_bus)
    }

    /// 注册事件监听器（便捷方法）；未初始化时静默跳过。
    /// Register a listener; no-op when the manager is not initialized.
    ///
    /// # 示例
    /// ```rust,ignore
    /// StpUtil::register_listener(Arc::new(MyListener));
    /// ```
    pub fn register_listener(listener: Arc<dyn SaTokenListener>) {
        if let Some(bus) = Self::event_bus() {
            bus.register(listener);
        }
    }

    // ==================== 登录相关 ====================

    /// 会话登录
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 支持字符串 ID
    /// let token = StpUtil::login("user_123").await?;
    ///
    /// // 支持数字 ID
    /// let token = StpUtil::login(10001).await?;
    /// let token = StpUtil::login(10001_i64).await?;
    /// ```
    pub async fn login(login_id: impl LoginId) -> SaTokenResult<TokenValue> {
        Self::try_get_manager()?.login(login_id.to_login_id()).await
    }

    /// `login_with_type` — login with type | `login_with_type`
    pub async fn login_with_type(
        login_id: impl LoginId,
        login_type: impl Into<String>,
    ) -> SaTokenResult<TokenValue> {
        Self::try_get_manager()?
            .login_with_options(
                login_id.to_login_id(),
                Some(login_type.into()),
                None,
                None,
                None,
                None,
            )
            .await
    }

    /// 登录并设置额外数据 | Login with extra data
    ///
    /// # 参数 | Arguments
    /// * `login_id` - 登录ID | Login ID
    /// * `extra_data` - 额外数据 | Extra data
    pub async fn login_with_extra(
        login_id: impl LoginId,
        extra_data: serde_json::Value,
    ) -> SaTokenResult<TokenValue> {
        Self::try_get_manager()?
            .login_with_options(
                login_id.to_login_id(),
                None, // login_type
                None, // device
                Some(extra_data),
                None, // nonce
                None, // expire_time
            )
            .await
    }

    /// 会话登录（带 manager 参数的版本，向后兼容）
    pub async fn login_with_manager(
        manager: &SaTokenManager,
        login_id: impl Into<String>,
    ) -> SaTokenResult<TokenValue> {
        manager.login(login_id).await
    }

    /// 会话登出
    pub async fn logout(token: &TokenValue) -> SaTokenResult<()> {
        tracing::debug!("开始执行 logout，token: {}", token);
        let result = Self::try_get_manager()?.logout(token).await;
        match &result {
            Ok(_) => tracing::debug!("logout 执行成功，token: {}", token),
            Err(e) => tracing::debug!("logout 执行失败，token: {}, 错误: {}", token, e),
        }
        result
    }

    /// `logout_with_manager` — logout with manager | `logout_with_manager`
    pub async fn logout_with_manager(
        manager: &SaTokenManager,
        token: &TokenValue,
    ) -> SaTokenResult<()> {
        manager.logout(token).await
    }

    /// Opt-in write of the token cookie (no-op unless `is_write_cookie` is true).
    /// 可选写入 token Cookie（未开启 `is_write_cookie` 时为空操作）。
    pub fn write_token_cookie<R: sa_token_adapter::context::SaResponse>(
        res: &mut R,
        token: &TokenValue,
    ) -> SaTokenResult<()> {
        let manager = Self::try_get_manager()?;
        crate::token_io::write_token_cookie(res, token, &manager.config);
        Ok(())
    }

    /// Clear the token cookie (same opt-in guard as write).
    /// 清除 token Cookie（与写入同一开关）。
    pub fn delete_token_cookie<R: sa_token_adapter::context::SaResponse>(
        res: &mut R,
    ) -> SaTokenResult<()> {
        let manager = Self::try_get_manager()?;
        crate::token_io::delete_token_cookie(res, &manager.config);
        Ok(())
    }

    /// Set per-token idle timeout. No-op unless `dynamic_active_timeout` is enabled.
    /// 设置单 token 闲置超时。未打开 `dynamic_active_timeout` 时返回 ConfigError。
    pub async fn update_active_timeout(token: &TokenValue, seconds: i64) -> SaTokenResult<()> {
        let mgr = Self::try_get_manager()?;
        if !mgr.config.dynamic_active_timeout {
            return Err(SaTokenError::ConfigError(
                "dynamic_active_timeout is disabled".into(),
            ));
        }
        let mut info = mgr.get_token_info(token).await?;
        info.active_timeout_override = Some(seconds);
        mgr.token_repo().save_token_info(&info).await
    }

    /// 踢人下线（使用当前请求 login_type，无上下文则 default）
    /// Kick out (uses current request login_type; falls back to default).
    pub async fn kick_out(login_id: impl LoginId) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::kick_out_with_type(login_type.as_ref(), login_id).await
    }

    /// `kick_out_with_type` — kick out with type | `kick_out_with_type`
    pub async fn kick_out_with_type(login_type: &str, login_id: impl LoginId) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .kick_out(login_type, &login_id.to_login_id())
            .await
    }

    /// `kick_out_with_manager` — kick out with manager | `kick_out_with_manager`
    pub async fn kick_out_with_manager(
        manager: &SaTokenManager,
        login_type: &str,
        login_id: impl LoginId,
    ) -> SaTokenResult<()> {
        manager.kick_out(login_type, &login_id.to_login_id()).await
    }

    /// 强制登出（使用当前请求 login_type，无上下文则 default）
    /// Force logout by login_id (uses current request login_type; falls back to default).
    pub async fn logout_by_login_id(login_id: impl LoginId) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::logout_by_login_id_with_type(login_type.as_ref(), login_id).await
    }

    /// `logout_by_login_id_with_type` — logout by login id with type | `logout_by_login_id_with_type`
    pub async fn logout_by_login_id_with_type(
        login_type: &str,
        login_id: impl LoginId,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .logout_by_login_id(login_type, &login_id.to_login_id())
            .await
    }

    /// 根据 token 登出（别名方法，更直观）
    pub async fn logout_by_token(token: &TokenValue) -> SaTokenResult<()> {
        Self::logout(token).await
    }

    // ==================== 当前会话操作（无参数，从上下文获取）====================

    /// 获取当前请求的 token（无参数，从上下文获取）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let token = StpUtil::get_token_value()?;
    /// ```
    pub fn get_token_value() -> SaTokenResult<TokenValue> {
        let ctx = SaTokenContext::try_current().ok_or(SaTokenError::NotLogin)?;
        ctx.token().ok_or(SaTokenError::NotLogin)
    }

    /// 当前会话登出（无参数，从上下文获取 token）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// StpUtil::logout_current().await?;
    /// ```
    pub async fn logout_current() -> SaTokenResult<()> {
        let token = Self::get_token_value()?;
        tracing::debug!("成功获取 token: {}", token);

        let result = Self::logout(&token).await;
        match &result {
            Ok(_) => tracing::debug!("logout_current 执行成功，token: {}", token),
            Err(e) => tracing::debug!("logout_current 执行失败，token: {}, 错误: {}", token, e),
        }
        result
    }

    /// 检查当前会话是否登录（同步弱校验：仅看上下文是否有 token 字符串，不查存储）
    /// Sync weak check: whether context has a token string (does not hit storage).
    ///
    /// 踢出/过期后若中间件未刷新上下文，仍可能为 true。强保证用 [`check_login_current_async`]。
    /// May still be true after kick/expire if middleware did not refresh context.
    pub fn is_login_current() -> bool {
        Self::get_token_value().is_ok()
    }

    /// 检查当前会话登录状态（同步弱校验），未登录则抛出异常
    /// Sync weak check; returns error when context has no token.
    pub fn check_login_current() -> SaTokenResult<()> {
        Self::get_token_value()?;
        Ok(())
    }

    /// 异步强校验：上下文有 token 且 storage 仍有效
    /// Async strong check: context has a token AND storage still considers it valid.
    pub async fn check_login_current_async() -> SaTokenResult<()> {
        let token = Self::get_token_value()?;
        if !Self::try_get_manager()?.is_valid(&token).await {
            return Err(SaTokenError::NotLogin);
        }
        Ok(())
    }

    /// 异步强校验是否登录
    /// Async strong login check returning bool.
    pub async fn is_login_current_async() -> bool {
        Self::check_login_current_async().await.is_ok()
    }

    /// 获取当前会话的 login_id（String 类型，无参数）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let login_id = StpUtil::get_login_id_as_string().await?;
    /// ```
    pub async fn get_login_id_as_string() -> SaTokenResult<String> {
        if let Some(ctx) = SaTokenContext::get_current() {
            if let Some(switch_id) = ctx.switch_login_id() {
                return Ok(switch_id);
            }
        }
        let token = Self::get_token_value()?;
        Self::get_login_id(&token).await
    }

    /// 获取当前会话的 login_id（i64 类型，无参数）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let user_id = StpUtil::get_login_id_as_long().await?;
    /// ```
    pub async fn get_login_id_as_long() -> SaTokenResult<i64> {
        let login_id_str = Self::get_login_id_as_string().await?;
        login_id_str
            .parse::<i64>()
            .map_err(|_| SaTokenError::LoginIdNotNumber)
    }

    /// 获取当前会话的 token 信息（无参数）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let token_info = StpUtil::get_token_info_current()?;
    /// println!("Token 创建时间: {:?}", token_info.create_time);
    /// ```
    pub fn get_token_info_current() -> SaTokenResult<Arc<TokenInfo>> {
        let ctx = SaTokenContext::try_current().ok_or(SaTokenError::NotLogin)?;
        ctx.token_info().ok_or(SaTokenError::NotLogin)
    }

    // ==================== Token 验证 ====================

    /// 检查当前 token 是否已登录
    pub async fn is_login(token: &TokenValue) -> bool {
        let Ok(manager) = Self::try_get_manager() else {
            return false;
        };
        manager.is_valid(token).await
    }

    /// 根据登录 ID 检查是否已登录
    ///
    /// # 示例
    /// ```rust,ignore
    /// let is_logged_in = StpUtil::is_login_by_login_id("user_123").await;
    /// let is_logged_in = StpUtil::is_login_by_login_id(10001).await;
    /// ```
    pub async fn is_login_by_login_id(login_id: impl LoginId) -> bool {
        match Self::get_token_by_login_id(login_id).await {
            Ok(token) => Self::is_login(&token).await,
            Err(_) => false,
        }
    }

    /// `is_login_with_manager` — is login with manager | `is_login_with_manager`
    pub async fn is_login_with_manager(manager: &SaTokenManager, token: &TokenValue) -> bool {
        manager.is_valid(token).await
    }

    /// 检查当前 token 是否已登录，如果未登录则抛出异常
    pub async fn check_login(token: &TokenValue) -> SaTokenResult<()> {
        if !Self::is_login(token).await {
            return Err(SaTokenError::NotLogin);
        }
        Ok(())
    }

    /// 获取 token 信息
    pub async fn get_token_info(token: &TokenValue) -> SaTokenResult<TokenInfo> {
        Self::try_get_manager()?.get_token_info(token).await
    }

    /// 获取当前 token 的登录ID
    pub async fn get_login_id(token: &TokenValue) -> SaTokenResult<String> {
        let token_info = Self::try_get_manager()?.get_token_info(token).await?;
        Ok(token_info.login_id.to_string())
    }

    /// 获取当前 token 的登录ID，如果未登录则返回默认值
    pub async fn get_login_id_or_default(token: &TokenValue, default: impl Into<String>) -> String {
        Self::get_login_id(token)
            .await
            .unwrap_or_else(|_| default.into())
    }

    /// 根据登录 ID 获取当前用户的 token
    ///
    /// # 示例
    /// ```rust,ignore
    /// let token = StpUtil::get_token_by_login_id("user_123").await?;
    /// let token = StpUtil::get_token_by_login_id(10001).await?;
    /// ```
    pub async fn get_token_by_login_id(login_id: impl LoginId) -> SaTokenResult<TokenValue> {
        let login_type = Self::resolve_login_type();
        Self::get_token_by_login_id_with_type(login_type.as_ref(), login_id).await
    }

    /// 指定 login_type 获取当前账号的 login:token 映射。
    ///
    /// 委托 Manager，禁止 StpUtil 直连 TokenRepo。
    pub async fn get_token_by_login_id_with_type(
        login_type: &str,
        login_id: impl LoginId,
    ) -> SaTokenResult<TokenValue> {
        Self::try_get_manager()?
            .get_token_by_login_id(login_type, &login_id.to_login_id())
            .await
    }

    /// `get_all_tokens_by_login_id` — get all tokens by login id | `get_all_tokens_by_login_id`
    pub async fn get_all_tokens_by_login_id(
        login_id: impl LoginId,
    ) -> SaTokenResult<Vec<TokenValue>> {
        let login_type = Self::resolve_login_type();
        Self::get_all_tokens_by_login_id_with_type(login_type.as_ref(), login_id).await
    }

    /// 指定 login_type 获取全部在线 token。
    ///
    /// 委托 Manager（内部走 TokenRepo list 原语）。
    pub async fn get_all_tokens_by_login_id_with_type(
        login_type: &str,
        login_id: impl LoginId,
    ) -> SaTokenResult<Vec<TokenValue>> {
        Self::try_get_manager()?
            .get_all_tokens_by_login_id(login_type, &login_id.to_login_id())
            .await
    }

    // ==================== Session 会话 ====================

    /// `get_session_with_type` — get session with type | `get_session_with_type`
    pub async fn get_session_with_type(
        login_type: &str,
        login_id: impl LoginId,
    ) -> SaTokenResult<SaSession> {
        Self::try_get_manager()?
            .get_session_with_type(login_type, &login_id.to_login_id())
            .await
    }

    /// `delete_session_with_type` — delete session with type | `delete_session_with_type`
    pub async fn delete_session_with_type(
        login_type: &str,
        login_id: impl LoginId,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .delete_session_with_type(login_type, &login_id.to_login_id())
            .await
    }

    /// 获取当前登录账号的 Session（使用当前请求 login_type）
    /// Get session for login_id (uses current request login_type).
    pub async fn get_session(login_id: impl LoginId) -> SaTokenResult<SaSession> {
        let login_type = Self::resolve_login_type();
        Self::get_session_with_type(login_type.as_ref(), login_id).await
    }

    /// 保存 Session
    pub async fn save_session(session: &SaSession) -> SaTokenResult<()> {
        Self::try_get_manager()?.save_session(session).await
    }

    /// 删除 Session（使用当前请求 login_type）
    /// Delete session (uses current request login_type).
    pub async fn delete_session(login_id: impl LoginId) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::delete_session_with_type(login_type.as_ref(), login_id).await
    }

    /// 在 Session 中设置值（使用当前请求 login_type）
    /// Set a value in session (uses current request login_type).
    pub async fn set_session_value<T: serde::Serialize>(
        login_id: impl LoginId,
        key: &str,
        value: T,
    ) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        let manager = Self::try_get_manager()?;
        let login_id_str = login_id.to_login_id();
        let mut session = manager
            .get_session_with_type(login_type.as_ref(), &login_id_str)
            .await?;
        session.set(key, value)?;
        manager.save_session(&session).await
    }

    /// 从 Session 中获取值（使用当前请求 login_type）
    /// Get a value from session (uses current request login_type).
    pub async fn get_session_value<T: serde::de::DeserializeOwned>(
        login_id: impl LoginId,
        key: &str,
    ) -> SaTokenResult<Option<T>> {
        let login_type = Self::resolve_login_type();
        let session = Self::get_session_with_type(login_type.as_ref(), login_id).await?;
        Ok(session.get::<T>(key))
    }

    // ==================== Token 相关 ====================

    /// 创建一个新的 token（但不登录）
    pub fn create_token(token_value: impl Into<String>) -> TokenValue {
        TokenValue::new(token_value.into())
    }

    /// 检查 token 格式是否有效（仅检查格式，不检查是否存在于存储中）
    pub fn is_valid_token_format(token: &str) -> bool {
        !token.is_empty() && token.len() >= 16
    }
}

impl std::fmt::Debug for StpUtil {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StpUtil { .. }")
    }
}

// ==================== 权限管理 ====================

impl StpUtil {
    // ---------- 权限：写入 | Permissions: writes ----------

    /// 覆盖权限列表（指定账号体系）| Overwrite permissions for a login type
    pub async fn set_permissions_with_type(
        login_type: &str,
        login_id: impl LoginId,
        permissions: Vec<String>,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .set_permissions_with_type(login_type, &login_id.to_login_id(), permissions)
            .await
    }

    /// 覆盖权限列表 | Overwrite permissions
    pub async fn set_permissions(
        login_id: impl LoginId,
        permissions: Vec<String>,
    ) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::set_permissions_with_type(&login_type, login_id, permissions).await
    }

    /// 追加单个权限（指定账号体系）| Append one permission for a login type
    pub async fn add_permission_with_type(
        login_type: &str,
        login_id: impl LoginId,
        permission: impl Into<String>,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .add_permission_with_type(login_type, &login_id.to_login_id(), permission.into())
            .await
    }

    /// 追加单个权限 | Append one permission
    pub async fn add_permission(
        login_id: impl LoginId,
        permission: impl Into<String>,
    ) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::add_permission_with_type(&login_type, login_id, permission).await
    }

    /// 移除单个权限（指定账号体系）| Remove one permission for a login type
    pub async fn remove_permission_with_type(
        login_type: &str,
        login_id: impl LoginId,
        permission: &str,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .remove_permission_with_type(login_type, &login_id.to_login_id(), permission)
            .await
    }

    /// 移除单个权限 | Remove one permission
    pub async fn remove_permission(login_id: impl LoginId, permission: &str) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::remove_permission_with_type(&login_type, login_id, permission).await
    }

    /// 清空权限（指定账号体系）| Clear permissions for a login type
    pub async fn clear_permissions_with_type(
        login_type: &str,
        login_id: impl LoginId,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .clear_permissions_with_type(login_type, &login_id.to_login_id())
            .await
    }

    /// 清空权限 | Clear permissions
    pub async fn clear_permissions(login_id: impl LoginId) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::clear_permissions_with_type(&login_type, login_id).await
    }

    // ---------- 权限：读取 | Permissions: reads ----------

    /// 获取权限列表（指定账号体系，错误上抛）
    /// Permission list for a login type, propagating errors.
    pub async fn try_get_permissions_with_type(
        login_type: &str,
        login_id: impl LoginId,
    ) -> SaTokenResult<Vec<String>> {
        Self::try_get_manager()?
            .get_permissions_with_type(login_type, &login_id.to_login_id())
            .await
    }

    /// 获取权限列表（错误上抛，修 B2-39）
    /// Unlike `get_permissions`, this propagates storage failures.
    pub async fn try_get_permissions(login_id: impl LoginId) -> SaTokenResult<Vec<String>> {
        let login_type = Self::resolve_login_type();
        Self::try_get_permissions_with_type(&login_type, login_id).await
    }

    /// 获取权限列表（失败返回空表 + 告警日志，修 B2-39）
    /// Keeps the old signature; failures now log a warning instead of being silent.
    pub async fn get_permissions(login_id: impl LoginId) -> Vec<String> {
        let login_id = login_id.to_login_id();
        match Self::try_get_permissions(&login_id).await {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!(
                    login_id = %login_id,
                    error = %e,
                    "failed to load permissions, treating as empty"
                );
                Vec::new()
            }
        }
    }

    // ---------- 权限：校验 | Permissions: checks ----------

    /// 单个权限校验（指定账号体系）| Single permission check for a login type
    pub async fn has_permission_with_type(
        login_type: &str,
        login_id: impl LoginId,
        permission: &str,
    ) -> bool {
        let Ok(manager) = Self::try_get_manager() else {
            return false;
        };
        manager
            .authz_service()
            .has_permission(login_type, &login_id.to_login_id(), permission)
            .await
            .unwrap_or(false)
    }

    /// 单个权限校验 | Single permission check
    pub async fn has_permission(login_id: impl LoginId, permission: &str) -> bool {
        let login_type = Self::resolve_login_type();
        Self::has_permission_with_type(&login_type, login_id, permission).await
    }

    /// 批量权限校验（AND，指定账号体系）| Batch AND check for a login type
    pub async fn has_all_permissions_with_type(
        login_type: &str,
        login_id: impl LoginId,
        permissions: &[&str],
    ) -> bool {
        let Ok(manager) = Self::try_get_manager() else {
            return false;
        };
        manager
            .authz_service()
            .has_all_permissions(login_type, &login_id.to_login_id(), permissions)
            .await
            .unwrap_or(false)
    }

    /// 批量权限校验（AND）| Batch AND check
    pub async fn has_all_permissions(login_id: impl LoginId, permissions: &[&str]) -> bool {
        let login_type = Self::resolve_login_type();
        Self::has_all_permissions_with_type(&login_type, login_id, permissions).await
    }

    /// [`has_all_permissions`](Self::has_all_permissions) 的别名 | Alias
    pub async fn has_permissions_and(login_id: impl LoginId, permissions: &[&str]) -> bool {
        Self::has_all_permissions(login_id, permissions).await
    }

    /// 批量权限校验（OR，指定账号体系）| Batch OR check for a login type
    pub async fn has_any_permission_with_type(
        login_type: &str,
        login_id: impl LoginId,
        permissions: &[&str],
    ) -> bool {
        let Ok(manager) = Self::try_get_manager() else {
            return false;
        };
        manager
            .authz_service()
            .has_any_permission(login_type, &login_id.to_login_id(), permissions)
            .await
            .unwrap_or(false)
    }

    /// 批量权限校验（OR）| Batch OR check
    pub async fn has_any_permission(login_id: impl LoginId, permissions: &[&str]) -> bool {
        let login_type = Self::resolve_login_type();
        Self::has_any_permission_with_type(&login_type, login_id, permissions).await
    }

    /// [`has_any_permission`](Self::has_any_permission) 的别名 | Alias
    pub async fn has_permissions_or(login_id: impl LoginId, permissions: &[&str]) -> bool {
        Self::has_any_permission(login_id, permissions).await
    }

    /// 权限校验（失败返回 `Err`，指定账号体系）
    /// Permission check returning `Err` on denial, for a login type.
    pub async fn check_permission_with_type(
        login_type: &str,
        login_id: impl LoginId,
        permission: &str,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .authz_service()
            .check_permission(login_type, &login_id.to_login_id(), permission)
            .await
    }

    /// 权限校验（失败返回 `Err`）| Permission check returning `Err` on denial
    pub async fn check_permission(login_id: impl LoginId, permission: &str) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::check_permission_with_type(&login_type, login_id, permission).await
    }

    /// 批量权限校验（AND，失败返回 `Err`，B2-36 新增）
    /// Batch AND check returning `Err` on denial.
    pub async fn check_all_permissions(
        login_id: impl LoginId,
        permissions: &[&str],
    ) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::try_get_manager()?
            .authz_service()
            .check_all_permissions(&login_type, &login_id.to_login_id(), permissions)
            .await
    }

    /// 批量权限校验（OR，失败返回 `Err`，B2-36 新增）
    /// Batch OR check returning `Err` on denial.
    pub async fn check_any_permission(
        login_id: impl LoginId,
        permissions: &[&str],
    ) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::try_get_manager()?
            .authz_service()
            .check_any_permission(&login_type, &login_id.to_login_id(), permissions)
            .await
    }
}

// ==================== 角色管理 ====================

impl StpUtil {
    // ---------- 角色：写入 | Roles: writes ----------

    /// 覆盖角色列表（指定账号体系）| Overwrite roles for a login type
    pub async fn set_roles_with_type(
        login_type: &str,
        login_id: impl LoginId,
        roles: Vec<String>,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .set_roles_with_type(login_type, &login_id.to_login_id(), roles)
            .await
    }

    /// 覆盖角色列表 | Overwrite roles
    pub async fn set_roles(login_id: impl LoginId, roles: Vec<String>) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::set_roles_with_type(&login_type, login_id, roles).await
    }

    /// 追加单个角色（指定账号体系）| Append one role for a login type
    pub async fn add_role_with_type(
        login_type: &str,
        login_id: impl LoginId,
        role: impl Into<String>,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .add_role_with_type(login_type, &login_id.to_login_id(), role.into())
            .await
    }

    /// 追加单个角色 | Append one role
    pub async fn add_role(login_id: impl LoginId, role: impl Into<String>) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::add_role_with_type(&login_type, login_id, role).await
    }

    /// 移除单个角色（指定账号体系）| Remove one role for a login type
    pub async fn remove_role_with_type(
        login_type: &str,
        login_id: impl LoginId,
        role: &str,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .remove_role_with_type(login_type, &login_id.to_login_id(), role)
            .await
    }

    /// 移除单个角色 | Remove one role
    pub async fn remove_role(login_id: impl LoginId, role: &str) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::remove_role_with_type(&login_type, login_id, role).await
    }

    /// 清空角色（指定账号体系）| Clear roles for a login type
    pub async fn clear_roles_with_type(
        login_type: &str,
        login_id: impl LoginId,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .clear_roles_with_type(login_type, &login_id.to_login_id())
            .await
    }

    /// 清空角色 | Clear roles
    pub async fn clear_roles(login_id: impl LoginId) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::clear_roles_with_type(&login_type, login_id).await
    }

    // ---------- 角色：读取 | Roles: reads ----------

    /// 获取角色列表（指定账号体系，错误上抛）
    /// Role list for a login type, propagating errors.
    pub async fn try_get_roles_with_type(
        login_type: &str,
        login_id: impl LoginId,
    ) -> SaTokenResult<Vec<String>> {
        Self::try_get_manager()?
            .get_roles_with_type(login_type, &login_id.to_login_id())
            .await
    }

    /// 获取角色列表（错误上抛，修 B2-39）| Role list propagating errors
    pub async fn try_get_roles(login_id: impl LoginId) -> SaTokenResult<Vec<String>> {
        let login_type = Self::resolve_login_type();
        Self::try_get_roles_with_type(&login_type, login_id).await
    }

    /// 获取角色列表（失败返回空表 + 告警日志）| Role list, empty on failure with a warning
    pub async fn get_roles(login_id: impl LoginId) -> Vec<String> {
        let login_id = login_id.to_login_id();
        match Self::try_get_roles(&login_id).await {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!(
                    login_id = %login_id,
                    error = %e,
                    "failed to load roles, treating as empty"
                );
                Vec::new()
            }
        }
    }

    // ---------- 角色：校验 | Roles: checks ----------

    /// 单个角色校验（指定账号体系）| Single role check for a login type
    pub async fn has_role_with_type(login_type: &str, login_id: impl LoginId, role: &str) -> bool {
        let Ok(manager) = Self::try_get_manager() else {
            return false;
        };
        manager
            .authz_service()
            .has_role(login_type, &login_id.to_login_id(), role)
            .await
            .unwrap_or(false)
    }

    /// 单个角色校验 | Single role check
    pub async fn has_role(login_id: impl LoginId, role: &str) -> bool {
        let login_type = Self::resolve_login_type();
        Self::has_role_with_type(&login_type, login_id, role).await
    }

    /// 批量角色校验（AND，指定账号体系）| Batch AND role check for a login type
    pub async fn has_all_roles_with_type(
        login_type: &str,
        login_id: impl LoginId,
        roles: &[&str],
    ) -> bool {
        let Ok(manager) = Self::try_get_manager() else {
            return false;
        };
        manager
            .authz_service()
            .has_all_roles(login_type, &login_id.to_login_id(), roles)
            .await
            .unwrap_or(false)
    }

    /// 批量角色校验（AND）| Batch AND role check
    pub async fn has_all_roles(login_id: impl LoginId, roles: &[&str]) -> bool {
        let login_type = Self::resolve_login_type();
        Self::has_all_roles_with_type(&login_type, login_id, roles).await
    }

    /// [`has_all_roles`](Self::has_all_roles) 的别名 | Alias
    pub async fn has_roles_and(login_id: impl LoginId, roles: &[&str]) -> bool {
        Self::has_all_roles(login_id, roles).await
    }

    /// 批量角色校验（OR，指定账号体系）| Batch OR role check for a login type
    pub async fn has_any_role_with_type(
        login_type: &str,
        login_id: impl LoginId,
        roles: &[&str],
    ) -> bool {
        let Ok(manager) = Self::try_get_manager() else {
            return false;
        };
        manager
            .authz_service()
            .has_any_role(login_type, &login_id.to_login_id(), roles)
            .await
            .unwrap_or(false)
    }

    /// 批量角色校验（OR）| Batch OR role check
    pub async fn has_any_role(login_id: impl LoginId, roles: &[&str]) -> bool {
        let login_type = Self::resolve_login_type();
        Self::has_any_role_with_type(&login_type, login_id, roles).await
    }

    /// [`has_any_role`](Self::has_any_role) 的别名 | Alias
    pub async fn has_roles_or(login_id: impl LoginId, roles: &[&str]) -> bool {
        Self::has_any_role(login_id, roles).await
    }

    /// 角色校验（失败返回 `Err`，指定账号体系）
    /// Role check returning `Err` on denial, for a login type.
    pub async fn check_role_with_type(
        login_type: &str,
        login_id: impl LoginId,
        role: &str,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .authz_service()
            .check_role(login_type, &login_id.to_login_id(), role)
            .await
    }

    /// 角色校验（失败返回 `Err`）| Role check returning `Err` on denial
    pub async fn check_role(login_id: impl LoginId, role: &str) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::check_role_with_type(&login_type, login_id, role).await
    }

    /// 批量角色校验（AND，失败返回 `Err`，B2-36 新增）
    /// Batch AND role check returning `Err`.
    pub async fn check_all_roles(login_id: impl LoginId, roles: &[&str]) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::try_get_manager()?
            .authz_service()
            .check_all_roles(&login_type, &login_id.to_login_id(), roles)
            .await
    }

    /// 批量角色校验（OR，失败返回 `Err`，B2-36 新增）
    /// Batch OR role check returning `Err`.
    pub async fn check_any_role(login_id: impl LoginId, roles: &[&str]) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::try_get_manager()?
            .authz_service()
            .check_any_role(&login_type, &login_id.to_login_id(), roles)
            .await
    }
}

// ==================== 封禁（disable） ====================

impl StpUtil {
    /// 封禁账号（默认服务 login；使用当前请求 login_type）
    /// Disable account (default service; uses current request login_type).
    pub async fn disable(login_id: impl LoginId, time: i64) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::try_get_manager()?
            .disable_with_type(login_type.as_ref(), &login_id.to_login_id(), time)
            .await
    }

    /// 指定 login_type 封禁
    /// Disable with explicit login_type.
    pub async fn disable_with_type(
        login_type: &str,
        login_id: impl LoginId,
        time: i64,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .disable_with_type(login_type, &login_id.to_login_id(), time)
            .await
    }

    /// 封禁账号指定服务与等级（使用当前请求 login_type）
    /// Disable with service/level (uses current request login_type).
    pub async fn disable_level(
        login_id: impl LoginId,
        service: &str,
        level: i32,
        time: i64,
    ) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::try_get_manager()?
            .disable_level_with_type(
                login_type.as_ref(),
                &login_id.to_login_id(),
                service,
                level,
                time,
            )
            .await
    }

    /// 校验封禁（默认服务 login、最低等级）
    pub async fn check_disable(login_id: impl LoginId) -> SaTokenResult<()> {
        Self::check_disable_level(
            login_id,
            crate::disable::DEFAULT_DISABLE_SERVICE,
            crate::disable::MIN_DISABLE_LEVEL,
        )
        .await
    }

    /// 校验指定服务的封禁
    pub async fn check_disable_service(login_id: impl LoginId, service: &str) -> SaTokenResult<()> {
        Self::check_disable_level(login_id, service, crate::disable::MIN_DISABLE_LEVEL).await
    }

    /// 校验多个服务的封禁（使用当前请求 login_type）
    pub async fn check_disable_services(
        login_id: impl LoginId,
        services: &[&str],
    ) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::try_get_manager()?
            .check_disable_services_with_type(
                login_type.as_ref(),
                &login_id.to_login_id(),
                services,
                crate::disable::MIN_DISABLE_LEVEL,
            )
            .await
    }

    /// 校验封禁等级（使用当前请求 login_type）
    pub async fn check_disable_level(
        login_id: impl LoginId,
        service: &str,
        level: i32,
    ) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::try_get_manager()?
            .check_disable_level_with_type(
                login_type.as_ref(),
                &login_id.to_login_id(),
                service,
                level,
            )
            .await
    }

    /// 获取封禁等级（使用当前请求 login_type）
    /// Get disable level (uses current request login_type).
    pub async fn get_disable_level(login_id: impl LoginId, service: &str) -> SaTokenResult<i32> {
        let login_type = Self::resolve_login_type();
        Self::get_disable_level_with_type(login_type.as_ref(), login_id, service).await
    }

    /// 指定 login_type 获取封禁等级
    /// Get disable level with explicit login_type.
    pub async fn get_disable_level_with_type(
        login_type: &str,
        login_id: impl LoginId,
        service: &str,
    ) -> SaTokenResult<i32> {
        Self::try_get_manager()?
            .get_disable_level_with_type(login_type, &login_id.to_login_id(), service)
            .await
    }

    /// 解封（使用当前请求 login_type）
    pub async fn untie_disable(login_id: impl LoginId, service: &str) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        Self::try_get_manager()?
            .untie_disable_with_type(login_type.as_ref(), &login_id.to_login_id(), service)
            .await
    }
}

// ==================== 二级认证（safe） ====================

impl StpUtil {
    /// 为当前 token 开启二级认证
    pub async fn open_safe(service: &str, safe_time: i64) -> SaTokenResult<()> {
        let token = Self::get_token_value()?;
        Self::try_get_manager()?
            .open_safe(&token, service, safe_time)
            .await
    }

    /// 当前 token 是否已通过二级认证
    pub async fn is_safe(service: &str) -> SaTokenResult<bool> {
        let token = Self::get_token_value()?;
        Self::try_get_manager()?.is_safe(&token, service).await
    }

    /// 校验当前 token 的二级认证
    pub async fn check_safe(service: &str) -> SaTokenResult<()> {
        Self::check_login_current()?;
        let token = Self::get_token_value()?;
        Self::try_get_manager()?.check_safe(&token, service).await
    }

    /// 关闭当前 token 的二级认证
    pub async fn close_safe(service: &str) -> SaTokenResult<()> {
        let token = Self::get_token_value()?;
        Self::try_get_manager()?.close_safe(&token, service).await
    }
}

// ==================== 身份临时切换（B3 核心修复）| Identity Switch (B3 core fix) ====================

impl StpUtil {
    /// 临时切换为指定 login_id（写入请求上下文，task-local 与 thread-local 单轨就地突变）
    ///
    /// Temporarily switch to the specified login_id (in-place mutation across task-local and thread-local).
    pub fn switch_to(login_id: impl LoginId) {
        let target = login_id.to_login_id();
        SaTokenContext::with_current_mut(|inner| {
            inner.switch_login_id = Some(target);
        });
    }

    /// 结束临时身份切换（清除 `switch_login_id`，恢复真实身份）
    ///
    /// End identity switch (clears `switch_login_id`, restoring real identity).
    pub fn end_switch() {
        SaTokenContext::with_current_mut(|inner| {
            inner.switch_login_id = None;
        });
    }

    /// 是否处于临时身份切换中
    ///
    /// Whether currently inside an identity switch.
    pub fn is_switch() -> bool {
        SaTokenContext::get_current()
            .and_then(|c| c.switch_login_id())
            .is_some()
    }

    /// 获取临时切换的 login_id（审计日志用）
    ///
    /// Get the switched login_id (for audit logs).
    pub fn get_switch_login_id() -> Option<String> {
        SaTokenContext::get_current().and_then(|c| c.switch_login_id())
    }
}

// ==================== 扩展工具方法 ====================

impl StpUtil {
    /// 批量踢人下线（使用当前请求 login_type）
    /// Batch kick-out (uses current request login_type).
    pub async fn kick_out_batch<T: LoginId>(
        login_ids: &[T],
    ) -> SaTokenResult<Vec<Result<(), SaTokenError>>> {
        let manager = Self::try_get_manager()?;
        let login_type = Self::resolve_login_type();
        let mut results = Vec::new();
        for login_id in login_ids {
            results.push(
                manager
                    .kick_out(login_type.as_ref(), &login_id.to_login_id())
                    .await,
            );
        }
        Ok(results)
    }

    /// 获取 token 剩余有效时间（秒）
    pub async fn get_token_timeout(token: &TokenValue) -> SaTokenResult<Option<i64>> {
        let manager = Self::try_get_manager()?;
        let token_info = manager.get_token_info(token).await?;

        if let Some(expire_time) = token_info.expire_time {
            let now = chrono::Utc::now();
            let duration = expire_time.signed_duration_since(now);
            Ok(Some(duration.num_seconds()))
        } else {
            Ok(None) // 永久有效
        }
    }

    /// 续期 token（重置过期时间）。
    ///
    /// 委托 Manager → AuthService，避免 StpUtil 直写 storage 与 B1 续签策略分叉。
    pub async fn renew_timeout(token: &TokenValue, timeout_seconds: i64) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .renew_timeout(token, timeout_seconds)
            .await
    }

    // ==================== 额外数据操作 | Extra Data Operations ====================

    /// 设置 Token 的额外数据。
    ///
    /// 委托 Manager::update_extra_data，禁止 StpUtil 直连 TokenRepo。
    pub async fn set_extra_data(
        token: &TokenValue,
        extra_data: serde_json::Value,
    ) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .update_extra_data(token, extra_data)
            .await
    }

    /// 获取 Token 的额外数据 | Get extra data from token
    ///
    /// # 参数 | Arguments
    /// * `token` - Token值 | Token value
    pub async fn get_extra_data(token: &TokenValue) -> SaTokenResult<Option<serde_json::Value>> {
        let manager = Self::try_get_manager()?;
        let token_info = manager.get_token_info(token).await?;
        Ok(token_info.extra_data)
    }

    // ==================== 终端信息 ====================

    /// List terminals for the account | 列出账号终端
    pub async fn get_terminal_list(
        login_id: &str,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<crate::session::SaTerminalInfo>> {
        let login_type = Self::resolve_login_type();
        Self::try_get_manager()?
            .get_terminal_list(login_type.as_ref(), login_id, device_type)
            .await
    }

    /// `get_token_value_list_by_login_id` — get token value list by login id | `get_token_value_list_by_login_id`
    pub async fn get_token_value_list_by_login_id(
        login_id: &str,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<String>> {
        let login_type = Self::resolve_login_type();
        Self::try_get_manager()?
            .get_token_value_list_by_login_id(login_type.as_ref(), login_id, device_type)
            .await
    }

    /// Terminal info for a token | 按 Token 查终端信息
    pub async fn get_terminal_info_by_token(
        token: &TokenValue,
    ) -> SaTokenResult<Option<crate::session::SaTerminalInfo>> {
        Self::try_get_manager()?
            .get_terminal_info_by_token(token)
            .await
    }

    /// Require the current token's device type to equal `expected` (exact match).
    /// 要求当前 token 的设备类型等于 `expected`（精确匹配，区分大小写）。
    pub async fn check_current_terminal(expected: &str) -> SaTokenResult<()> {
        Self::check_login_current_async().await?;
        let token = Self::get_token_value()?;
        let term = Self::get_terminal_info_by_token(&token).await?;
        let actual = term.map(|t| t.device_type).unwrap_or_default();
        if actual != expected {
            return Err(SaTokenError::TerminalDenied {
                expected: expected.to_string(),
                actual,
            });
        }
        Ok(())
    }

    // ==================== 多账号体系 ====================

    /// 创建绑定 login_type 的廉价 Clone 门面（无全局注册表）
    /// Create a cheap Clone facade for login_type (no global registry).
    pub fn stp_logic(login_type: &str) -> SaTokenResult<crate::stp_logic::SaLogic> {
        Ok(crate::stp_logic::SaLogic::new(
            login_type,
            Self::try_get_manager()?.as_ref().clone(),
        ))
    }

    /// 已废弃：SaLogic 为可克隆门面，无需注册
    /// Deprecated: SaLogic is a cloneable facade; nothing to register.
    #[deprecated(note = "SaLogic is a cloneable facade; use SaLogic::new / StpUtil::stp_logic")]
    pub fn put_stp_logic(_logic: crate::stp_logic::SaLogic) {}

    /// 已废弃：SaLogic 为可克隆门面，无需移除
    /// Deprecated: SaLogic is a cloneable facade; nothing to remove.
    #[deprecated(note = "SaLogic is a cloneable facade; nothing to remove")]
    pub fn remove_stp_logic(_login_type: &str) {}

    // ==================== Token Session ====================

    /// 获取 token-session
    pub async fn get_token_session(token: &TokenValue) -> SaTokenResult<SaSession> {
        Self::try_get_manager()?.get_token_session(token).await
    }

    /// 获取当前请求的 token-session
    pub async fn get_token_session_current() -> SaTokenResult<SaSession> {
        let token = Self::get_token_value()?;
        Self::get_token_session(&token).await
    }

    /// 保存 token-session
    pub async fn save_token_session(token: &TokenValue, session: &SaSession) -> SaTokenResult<()> {
        Self::try_get_manager()?
            .save_token_session(token, session)
            .await
    }

    /// 删除 token-session
    pub async fn delete_token_session(token: &TokenValue) -> SaTokenResult<()> {
        Self::try_get_manager()?.delete_token_session(token).await
    }

    /// 按 token 踢人下线
    pub async fn kick_out_by_token(token: &TokenValue) -> SaTokenResult<()> {
        Self::try_get_manager()?.kick_out_by_token(token).await
    }

    // ==================== 授权快照 | Grant Scope ====================

    /// 在一段异步逻辑内启用「授权快照」：期间同一账号的权限/角色只读一次。
    /// Enables a per-scope authorization snapshot inside an async block.
    pub async fn with_grant_scope<F, T>(future: F) -> T
    where
        F: Future<Output = T>,
    {
        crate::context::GrantScope::run(crate::context::GrantScope::new(), future).await
    }

    /// 组合校验：权限集合 ∪ 角色集合中任一命中即通过（供 `#[sa_check_or]` 宏使用）。
    /// Combined check: passes when any of the permissions or roles matches.
    pub async fn check_permission_or_role(
        login_id: impl LoginId,
        permissions: &[&str],
        roles: &[&str],
    ) -> SaTokenResult<()> {
        let login_type = Self::resolve_login_type();
        let login_id = login_id.to_login_id();
        let authz = Self::try_get_manager()?.authz_service();

        if !permissions.is_empty()
            && authz
                .has_any_permission(&login_type, &login_id, permissions)
                .await?
        {
            return Ok(());
        }
        if !roles.is_empty() && authz.has_any_role(&login_type, &login_id, roles).await? {
            return Ok(());
        }

        Err(SaTokenError::PermissionDeniedDetail(format!(
            "none of permissions [{}] or roles [{}] matched",
            permissions.join(", "),
            roles.join(", ")
        )))
    }

    // ==================== 链式调用 | Chain Call ====================

    /// 创建 Token 构建器，用于链式调用 | Create token builder for chain calls
    ///
    /// # 示例 | Example
    /// ```rust,ignore
    /// use serde_json::json;
    ///
    /// // 链式调用示例
    /// let token = StpUtil::builder("user_123")
    ///     .extra_data(json!({"ip": "192.168.1.1"}))
    ///     .device("pc")
    ///     .login_type("admin")
    ///     .login()
    ///     .await?;
    /// ```
    pub fn builder(login_id: impl LoginId) -> TokenBuilder {
        TokenBuilder::new(login_id.to_login_id())
    }

    // ---------- request sign | 请求签名 ----------

    /// Build a signer from config (`sign_secret_key`). Errors if the secret is missing.
    /// 用配置中的 `sign_secret_key` 构造签名器；密钥缺失则报错。
    pub fn request_sign() -> SaTokenResult<crate::sign::RequestSign> {
        let manager = Self::try_get_manager()?;
        let secret = manager
            .config
            .sign_secret_key
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SaTokenError::ConfigError("sign_secret_key is not configured".into()))?;
        Ok(
            crate::sign::RequestSign::new(secret, manager.config.sign_window_secs)
                .with_dao(manager.dao().clone()),
        )
    }

    /// Create signed params (`timestamp` + `nonce` + `sign`).
    /// 创建已签名参数（`timestamp` + `nonce` + `sign`）。
    pub async fn sign_params(
        params: std::collections::BTreeMap<String, String>,
    ) -> SaTokenResult<std::collections::BTreeMap<String, String>> {
        Self::request_sign()?.create_signed(params)
    }

    /// Verify request signature from the `sign` field.
    /// 校验请求中 `sign` 字段的签名。
    pub async fn check_sign(
        params: &std::collections::BTreeMap<String, String>,
    ) -> SaTokenResult<()> {
        let sign = params
            .get("sign")
            .cloned()
            .ok_or(SaTokenError::SignInvalid)?;
        Self::request_sign()?.verify_params(params, &sign).await
    }

    // ---------- same-token（委托已有模块，避免第二套 API）----------

    /// Get current Same-Token (create if missing).
    /// 获取当前 Same-Token（不存在则创建）。
    pub async fn get_same_token() -> SaTokenResult<String> {
        crate::same_token::get_token().await
    }

    /// Refresh Same-Token.
    /// 刷新 Same-Token。
    pub async fn refresh_same_token() -> SaTokenResult<String> {
        crate::same_token::refresh_token().await
    }

    /// Check a Same-Token value.
    /// 校验 Same-Token 值。
    pub async fn check_same_token(token: &str) -> SaTokenResult<()> {
        crate::same_token::check_token(token).await
    }

    // ---------- temp token ----------

    /// Create a short-lived temp token in the default namespace.
    /// 在默认命名空间创建短时临时令牌。
    pub async fn create_temp_token(
        value: impl Into<String>,
        timeout_secs: i64,
    ) -> SaTokenResult<String> {
        crate::temp_token::create_default(value, timeout_secs).await
    }

    /// Parse a temp token from the default namespace.
    /// 解析默认命名空间中的临时令牌。
    pub async fn parse_temp_token(
        token: &str,
    ) -> SaTokenResult<crate::temp_token::TempTokenRecord> {
        crate::temp_token::parse_default(token).await
    }

    /// Delete a temp token from the default namespace.
    /// 删除默认命名空间中的临时令牌。
    pub async fn delete_temp_token(token: &str) -> SaTokenResult<()> {
        crate::temp_token::delete_default(token).await
    }
}

/// Token 构建器 - 支持链式调用 | Token Builder - Supports chain calls
pub struct TokenBuilder {
    login_id: String,
    extra_data: Option<serde_json::Value>,
    device: Option<String>,
    login_type: Option<String>,
    nonce: Option<String>,
    expire_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl std::fmt::Debug for TokenBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenBuilder { .. }")
    }
}

impl TokenBuilder {
    /// 创建新的 Token 构建器 | Create new token builder
    pub fn new(login_id: String) -> Self {
        Self {
            login_id,
            extra_data: None,
            device: None,
            login_type: None,
            nonce: None,
            expire_time: None,
        }
    }

    /// 设置额外数据 | Set extra data
    pub fn extra_data(mut self, data: serde_json::Value) -> Self {
        self.extra_data = Some(data);
        self
    }

    /// 设置设备信息 | Set device info
    pub fn device(mut self, device: impl Into<String>) -> Self {
        self.device = Some(device.into());
        self
    }

    /// 设置登录类型 | Set login type
    pub fn login_type(mut self, login_type: impl Into<String>) -> Self {
        self.login_type = Some(login_type.into());
        self
    }

    /// 设置 nonce（需开启 enable_nonce）
    /// Set nonce (requires enable_nonce)
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// 设置绝对过期时间
    /// Set absolute expire time
    pub fn expire_time(mut self, expire_time: chrono::DateTime<chrono::Utc>) -> Self {
        self.expire_time = Some(expire_time);
        self
    }

    /// 执行登录：字段在登录前注入 LoginRequest 等价路径（login_with_options）。
    ///
    /// 如果不提供 login_id 参数，则使用构建器中的 login_id。
    /// 一次性带齐可选字段，由 AuthService 阶段写入保证索引/终端/映射一致。
    pub async fn login<T: LoginId>(self, login_id: Option<T>) -> SaTokenResult<TokenValue> {
        let manager = StpUtil::try_get_manager()?;
        let final_login_id = match login_id {
            Some(id) => id.to_login_id(),
            None => self.login_id,
        };
        manager
            .login_with_options(
                final_login_id,
                self.login_type,
                self.device,
                self.extra_data,
                self.nonce,
                self.expire_time,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_format_validation() {
        assert!(StpUtil::is_valid_token_format("1234567890abcdef"));
        assert!(!StpUtil::is_valid_token_format(""));
        assert!(!StpUtil::is_valid_token_format("short"));
    }

    #[test]
    fn test_create_token() {
        let token = StpUtil::create_token("test-token-123");
        assert_eq!(token.as_str(), "test-token-123");
    }
}
