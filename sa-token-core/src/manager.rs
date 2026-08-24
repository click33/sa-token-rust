// Author: 金书记
//
//! sa-token 管理器：对外 API 门面，业务逻辑委托给 service / repository 层。

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sa_token_adapter::storage::SaStorage;

use crate::config::SaTokenConfig;
use crate::dao::SaTokenDao;
use crate::distributed::DistributedSessionManager;
use crate::error::{SaTokenError, SaTokenResult};
use crate::event::SaTokenEventBus;
use crate::keys::{AccountNs, LOGIN_TYPE_DEFAULT, LoginId, SaKeyLayout, SaKeys};
use crate::online::OnlineManager;
use crate::permission::PermissionMatcher;
use crate::repository::{GrantRepo, SessionRepo, TokenRepo};
use crate::service::{AuthService, AuthzService, LoginRequest};
use crate::session::SaSession;
use crate::stp_interface::StpInterface;
use crate::token::{TokenInfo, TokenValue};

/// sa-token 管理器：对外 API 门面，业务逻辑委托给 service / repository 层。
///
/// The sa-token manager: a thin facade delegating to the service and
/// repository layers.
#[derive(Clone)]
pub struct SaTokenManager {
    /// 底层存储适配器。
    ///
    /// 与 `dao` 内部持有的是**同一个 `Arc`**，仅为兼容 crate 内既有的字段访问
    /// （`manager.rs` 单测与 `nonce.rs` / `refresh.rs` 等模块直接用 `self.storage`）。
    ///
    /// Shares the very same `Arc` as `dao`, kept only so existing in-crate field
    /// accesses keep compiling.
    pub(crate) storage: Arc<dyn SaStorage>,
    /// 对外兼容：`manager.config.token_name` 经 Deref 仍可用。
    /// Public field kept for compatibility; `Arc` derefs to `SaTokenConfig`.
    /// 构建期只包装一次，Clone Manager 只加引用计数，不再深拷贝配置。
    /// Wrapped once at construction; cloning the manager is a refcount bump.
    pub config: Arc<SaTokenConfig>,
    /// 键构造器：A3 契约要求持有而非每次 from_config（B1-1）
    keys: SaKeys,
    /// 事件总线 | Event bus
    pub(crate) event_bus: SaTokenEventBus,
    /// 存储访问层 | Storage access layer
    pub(crate) dao: Arc<SaTokenDao>,
    /// Token 仓储 | Token repository
    token_repo: Arc<TokenRepo>,
    /// Session 仓储 | Session repository
    session_repo: Arc<SessionRepo>,
    /// 授权仓储（纯存储；随 dao 变化重建）| Grant repository (storage only)
    grant_repo: Arc<GrantRepo>,
    /// 授权服务：权限/角色/封禁回落的唯一入口（随 stp_interface / matcher / 配置重建）
    /// Authorization service: the single entry point for grants and the ban
    /// fallback; rebuilt when the data source, matchers or config change.
    authz_service: Arc<AuthzService>,
    /// 认证服务（随 online_manager 变化重建）| Auth service, rebuilt with online_manager
    auth_service: Arc<AuthService>,
    /// 自定义权限匹配策略；`None` 表示使用默认分段匹配器。
    /// Custom permission matcher, `None` for the default segment matcher.
    perm_matcher: Option<Arc<dyn PermissionMatcher>>,
    /// 自定义角色匹配策略；`None` 表示按 `config.role_wildcard` 选择。
    /// Custom role matcher, `None` to pick exact/segment matching per config.
    role_matcher: Option<Arc<dyn PermissionMatcher>>,
    /// 在线用户管理器 | Online user manager
    online_manager: Option<Arc<OnlineManager>>,
    /// 分布式 Session 管理器 | Distributed session manager
    distributed_manager: Option<Arc<DistributedSessionManager>>,
    /// 权限/角色数据源回调 | Permission/role data source callback
    pub(crate) stp_interface: Option<Arc<dyn StpInterface>>,
}

impl std::fmt::Debug for SaTokenManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SaTokenManager { .. }")
    }
}

impl SaTokenManager {
    /// 创建管理器实例。
    ///
    /// 配置只包装一次进 `Arc`，此后各层共享，Clone Manager 不再深拷贝配置。
    /// Config is wrapped once into `Arc`; cloning the manager no longer deep-copies it.
    pub fn new(storage: Arc<dyn SaStorage>, config: SaTokenConfig) -> Self {
        let config = Arc::new(config);
        let keys = SaKeys::from_config(&config);
        let dao = Arc::new(SaTokenDao::new(storage.clone(), config.clone()));
        let event_bus = SaTokenEventBus::new();

        let token_repo = Arc::new(TokenRepo::new(dao.clone(), config.clone()));
        let session_repo = Arc::new(SessionRepo::new(dao.clone(), config.clone()));
        let grant_repo = Arc::new(GrantRepo::new(dao.clone()));

        let authz_service = Arc::new(AuthzService::new(
            grant_repo.clone(),
            &config,
            event_bus.clone(),
            None,
        ));

        let auth_service = Arc::new(AuthService::new(
            dao.clone(),
            config.clone(),
            token_repo.clone(),
            session_repo.clone(),
            event_bus.clone(),
            None,
            None,
        ));

        Self {
            storage,
            config,
            keys,
            event_bus,
            dao,
            token_repo,
            session_repo,
            grant_repo,
            authz_service,
            auth_service,
            perm_matcher: None,
            role_matcher: None,
            online_manager: None,
            distributed_manager: None,
            stp_interface: None,
        }
    }

    /// 重建依赖「后置注入项」的组件（修 B1-10、B2-4）。
    ///
    /// 授权链路一并重建：`GrantRepo` 随 `dao`，`AuthzService` 随
    /// `stp_interface` / matcher / 配置。重建意味着新实例缓存为空，
    /// 恰好满足「切换数据源后必须失效缓存」的要求。
    ///
    /// Rebuilds components that depend on post-construction injection. The
    /// authorization chain is rebuilt too; a fresh instance starts with an
    /// empty cache — exactly what "invalidate on data-source swap" requires.
    fn rebuild_services(&mut self) {
        self.grant_repo = Arc::new(GrantRepo::new(self.dao.clone()));

        let mut authz = AuthzService::new(
            self.grant_repo.clone(),
            &self.config,
            self.event_bus.clone(),
            self.stp_interface.clone(),
        );
        if let Some(matcher) = self.perm_matcher.clone() {
            authz = authz.with_permission_matcher(matcher);
        }
        if let Some(matcher) = self.role_matcher.clone() {
            authz = authz.with_role_matcher(matcher);
        }
        self.authz_service = Arc::new(authz);

        self.auth_service = Arc::new(AuthService::new(
            self.dao.clone(),
            self.config.clone(),
            self.token_repo.clone(),
            self.session_repo.clone(),
            self.event_bus.clone(),
            self.online_manager.clone(),
            self.distributed_manager.clone(),
        ));
    }

    /// 配置变更后重建 keys → dao → 仓储 → 服务整条链路。
    /// Rebuild keys → dao → repos → services after a config change.
    fn rebuild_config_chain(&mut self) {
        // 配置已是 Arc；只重建依赖它的键与仓储，不再二次包装。
        // Config is already Arc; rebuild keys/repos only.
        self.keys = SaKeys::from_config(&self.config);
        self.dao = Arc::new(SaTokenDao::new(self.storage.clone(), self.config.clone()));
        self.token_repo = Arc::new(TokenRepo::new(self.dao.clone(), self.config.clone()));
        self.session_repo = Arc::new(SessionRepo::new(self.dao.clone(), self.config.clone()));
        self.rebuild_services();
    }

    /// 运行时替换存储键布局（主要用于测试与迁移工具）
    pub fn with_key_layout(mut self, layout: SaKeyLayout) -> Self {
        Arc::make_mut(&mut self.config).key_layout = layout;
        self.rebuild_config_chain();
        self
    }

    /// 替换序列化器（如启用 fory）。
    ///
    /// 显式复用原 `event_bus`，避免丢弃已注册的监听器。
    pub fn with_serializer(
        mut self,
        serializer: sa_token_adapter::serializer::SharedSerializer,
    ) -> Self {
        Arc::make_mut(&mut self.config).serializer = serializer;
        self.rebuild_config_chain();
        self
    }

    /// 注册权限/角色数据源 | Register the permission/role data source
    pub fn with_stp_interface(mut self, iface: Arc<dyn StpInterface>) -> Self {
        self.stp_interface = Some(iface);
        self.rebuild_services();
        self
    }

    /// Replace the permission matcher used by AuthzService.
    /// 替换 AuthzService 使用的权限匹配器。
    pub fn with_permission_matcher(mut self, matcher: Arc<dyn PermissionMatcher>) -> Self {
        self.perm_matcher = Some(matcher);
        self.rebuild_services();
        self
    }

    /// 替换角色匹配策略（默认按 `config.role_wildcard` 选择精确/分段匹配）。
    /// Replaces the role matching strategy (default follows `config.role_wildcard`).
    pub fn with_role_matcher(mut self, matcher: Arc<dyn PermissionMatcher>) -> Self {
        self.role_matcher = Some(matcher);
        self.rebuild_services();
        self
    }

    /// 注册在线用户管理器 | Register the online user manager
    pub fn with_online_manager(mut self, manager: Arc<OnlineManager>) -> Self {
        self.online_manager = Some(manager);
        self.rebuild_services();
        self
    }

    /// 注册分布式 Session 管理器 | Register the distributed session manager
    pub fn with_distributed_manager(mut self, manager: Arc<DistributedSessionManager>) -> Self {
        self.distributed_manager = Some(manager);
        self.rebuild_services();
        self
    }

    /// Attach a Dao-backed online manager (cross-instance presence).
    /// 挂上基于 Dao 的在线管理器（跨实例 presence）。
    pub fn with_distributed_online(mut self) -> Self {
        self.online_manager = Some(Arc::new(OnlineManager::distributed(self.dao.clone())));
        self.rebuild_services();
        self
    }

    /// Start optional background cleanup (disabled unless `CleanupConfig.enabled`).
    /// 启动可选后台清理（除非 `CleanupConfig.enabled` 否则不跑）。
    pub fn start_background_cleanup(
        &self,
        config: crate::cleanup::CleanupConfig,
    ) -> crate::cleanup::BackgroundCleanupTask {
        let nonce = Arc::new(crate::nonce::NonceManager::from_dao(
            self.dao.clone(),
            if self.config.nonce_timeout > 0 {
                self.config.nonce_timeout
            } else {
                60
            },
        ));
        crate::cleanup::BackgroundCleanupTask::spawn(
            config,
            Some(nonce),
            self.online_manager.clone(),
        )
    }

    /// 注入共享事件总线（支持多 Manager 共享 / 测试 mock）
    ///
    /// Injects a shared event bus (supports multi-Manager sharing / test mocking).
    ///
    /// # 示例 | Example
    /// ```rust,ignore
    /// let shared_bus = SaTokenEventBus::with_config(EventBusConfig {
    ///     dispatch_mode: DispatchMode::Detached,
    ///     listener_timeout: Some(Duration::from_secs(10)),
    /// });
    /// let mgr1 = SaTokenManager::new(storage1, config1).with_event_bus(shared_bus.clone());
    /// let mgr2 = SaTokenManager::new(storage2, config2).with_event_bus(shared_bus.clone());
    /// shared_bus.register(Arc::new(MyListener));
    /// ```
    pub fn with_event_bus(mut self, event_bus: SaTokenEventBus) -> Self {
        self.event_bus = event_bus.clone();
        self.rebuild_services();
        self
    }

    // ---------- 访问器 | Accessors ----------

    /// 存储键构造器（A3 契约：返回引用，避免热路径克隆）
    #[inline]
    pub fn keys(&self) -> &SaKeys {
        &self.keys
    }

    /// 底层存储 | Underlying storage
    pub fn storage(&self) -> &Arc<dyn SaStorage> {
        &self.storage
    }

    /// 存储访问层 | Storage access layer
    pub fn dao(&self) -> &Arc<SaTokenDao> {
        &self.dao
    }

    /// 当前序列化器 | Current serializer
    pub fn serializer(&self) -> &sa_token_adapter::serializer::SharedSerializer {
        &self.config.serializer
    }

    /// 认证服务 | Authentication service
    pub fn auth_service(&self) -> &Arc<AuthService> {
        &self.auth_service
    }

    /// Token 仓储 | Token repository
    pub fn token_repo(&self) -> &Arc<TokenRepo> {
        &self.token_repo
    }

    /// Session 仓储 | Session repository
    pub fn session_repo(&self) -> &Arc<SessionRepo> {
        &self.session_repo
    }

    /// 授权服务：权限/角色的读写与校验入口 | Authorization service
    pub fn authz_service(&self) -> &Arc<AuthzService> {
        &self.authz_service
    }

    /// 授权仓储（**纯存储**，绕过数据源优先级与缓存失效）。
    /// 请改用 [`authz_service()`](Self::authz_service)。
    ///
    /// The storage-only grant repository, bypassing data-source precedence and
    /// cache invalidation. Use `authz_service()` instead.
    #[deprecated(
        since = "0.2.0",
        note = "Use SaTokenManager::authz_service() so cache invalidation and StpInterface precedence are honoured"
    )]
    pub fn grant_repo(&self) -> &Arc<GrantRepo> {
        &self.grant_repo
    }

    /// 事件总线 | Event bus
    pub fn event_bus(&self) -> &SaTokenEventBus {
        &self.event_bus
    }

    /// 在线用户管理器 | Online user manager
    pub fn online_manager(&self) -> Option<&Arc<OnlineManager>> {
        self.online_manager.as_ref()
    }

    /// 分布式 Session 管理器 | Distributed session manager
    pub fn distributed_manager(&self) -> Option<&Arc<DistributedSessionManager>> {
        self.distributed_manager.as_ref()
    }

    /// 账号命名空间（crate 内部使用，A3 契约返回 AccountNs）
    pub(crate) fn account_ns(&self, login_type: &str, login_id: &str) -> AccountNs {
        SaKeys::account_ns(login_type, &LoginId::new(login_id))
    }

    // ---------- 登录 / 登出 / 踢人 ----------

    /// 登录：为指定账号创建 token | Log in and issue a token
    pub async fn login(&self, login_id: impl Into<String>) -> SaTokenResult<TokenValue> {
        self.auth_service.login(LoginRequest::new(login_id)).await
    }

    /// 登录（完整可选参数）。签名保持不变以维持对外兼容，
    /// 内部转换为 `LoginRequest` 后委托 `AuthService`。
    pub async fn login_with_options(
        &self,
        login_id: impl Into<String>,
        login_type: Option<String>,
        device: Option<String>,
        extra_data: Option<serde_json::Value>,
        nonce: Option<String>,
        expire_time: Option<DateTime<Utc>>,
    ) -> SaTokenResult<TokenValue> {
        let mut req = LoginRequest::new(login_id);
        if let Some(lt) = login_type {
            req = req.login_type(lt);
        }
        if let Some(d) = device {
            req = req.device(d);
        }
        if let Some(e) = extra_data {
            req = req.extra_data(e);
        }
        if let Some(n) = nonce {
            req = req.nonce(n);
        }
        if let Some(t) = expire_time {
            req = req.expire_time(t);
        }
        self.auth_service.login(req).await
    }

    /// 登录：使用完整 TokenInfo（SSO / 自定义 token 场景）。
    pub async fn login_with_token_info(&self, token_info: TokenInfo) -> SaTokenResult<TokenValue> {
        let mut req = LoginRequest::new(token_info.login_id.as_ref())
            .login_type(token_info.login_type.as_ref());
        if let Some(d) = token_info.device.clone() {
            req = req.device(d);
        }
        if let Some(e) = token_info.extra_data.clone() {
            req = req.extra_data(e);
        }
        if let Some(n) = token_info.nonce.clone() {
            req = req.nonce(n);
        }
        if let Some(t) = token_info.expire_time {
            req = req.expire_time(t);
        }
        if !token_info.token.as_str().is_empty() {
            req = req.preset_token(token_info.token.as_str());
        }
        self.auth_service.login(req).await
    }

    /// 登出指定 token | Log out a token
    pub async fn logout(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.auth_service
            .logout(token, self.config.is_logout_keep_token_session)
            .await
    }

    /// 踢下线指定 token（标记 -5）| Kick out a token, marker `-5`
    pub async fn kick_out_by_token(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.auth_service
            .kick_out_by_token(token, self.config.is_logout_keep_token_session)
            .await
    }

    /// 顶下线指定 token（标记 -4）| Replace a token, marker `-4`
    pub async fn replaced_by_token(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.auth_service.logout_replaced(token).await
    }

    /// 按账号登出全部 token | Log out every token of an account
    pub async fn logout_by_login_id(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        self.auth_service
            .logout_by_login_id(login_type, login_id)
            .await
    }

    /// 按账号踢下线全部 token | Kick out every token of an account
    pub async fn kick_out(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        self.auth_service.kick_out(login_type, login_id).await
    }

    /// 读取并校验 token | Read and validate a token
    pub async fn get_token_info(&self, token: &TokenValue) -> SaTokenResult<TokenInfo> {
        self.auth_service.get_token_info(token).await
    }

    /// 按 login_type + login_id 读取当前映射 token
    /// Read the mapped token for login_type + login_id
    pub async fn get_token_by_login_id(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<TokenValue> {
        match self
            .token_repo()
            .get_login_mapping(login_type, login_id)
            .await?
        {
            Some(token_str) => Ok(TokenValue::new(token_str)),
            None => Err(SaTokenError::NotLogin),
        }
    }

    /// 列出在线 token（B1 list 原语）
    /// List online tokens (B1 list primitive)
    pub async fn get_all_tokens_by_login_id(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<TokenValue>> {
        let tokens = self.token_repo().list_tokens(login_type, login_id).await?;
        Ok(tokens.into_iter().map(TokenValue::new).collect())
    }

    /// 更新 extra_data 并经 TokenRepo 落盘
    /// Update extra_data and persist via TokenRepo
    pub async fn update_extra_data(
        &self,
        token: &TokenValue,
        extra_data: serde_json::Value,
    ) -> SaTokenResult<()> {
        let mut token_info = self.get_token_info(token).await?;
        token_info.extra_data = Some(extra_data);
        self.token_repo().save_token_info(&token_info).await
    }

    /// Set per-token idle timeout. Errors unless `dynamic_active_timeout` is on.
    /// 设置单 token 闲置超时。未开启 `dynamic_active_timeout` 时返回 ConfigError。
    pub async fn update_active_timeout(
        &self,
        token: &TokenValue,
        seconds: i64,
    ) -> SaTokenResult<()> {
        if !self.config.dynamic_active_timeout {
            return Err(SaTokenError::ConfigError(
                "dynamic_active_timeout is disabled".into(),
            ));
        }
        let mut info = self.get_token_info(token).await?;
        info.active_timeout_override = Some(seconds);
        self.token_repo().save_token_info(&info).await
    }

    /// 创建绑定 login_type 的廉价 Clone 门面
    /// Create a cheap Clone facade bound to login_type
    pub fn stp_logic(&self, login_type: &str) -> crate::stp_logic::SaLogic {
        crate::stp_logic::SaLogic::new(login_type, self.clone())
    }

    /// token 是否有效 | Whether the token is valid
    pub async fn is_valid(&self, token: &TokenValue) -> bool {
        self.auth_service.is_valid(token).await
    }

    /// 续期 token 到指定秒数 | Renew a token to an explicit lifetime
    pub async fn renew_timeout(
        &self,
        token: &TokenValue,
        timeout_seconds: i64,
    ) -> SaTokenResult<()> {
        self.auth_service
            .renew_timeout(token, timeout_seconds)
            .await
    }

    // ---------- Session 与终端 ----------

    /// 读取账号 Session（默认 login_type）
    pub async fn get_session(&self, login_id: &str) -> SaTokenResult<SaSession> {
        self.session_repo
            .get_account_session(LOGIN_TYPE_DEFAULT, login_id)
            .await
    }

    /// 读取账号 Session（指定 login_type，A3 契约）
    pub async fn get_session_with_type(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<SaSession> {
        self.session_repo
            .get_account_session(login_type, login_id)
            .await
    }

    /// 保存账号 Session（修 B1-9：以 session.id 自身作为命名空间回写）
    pub async fn save_session(&self, session: &SaSession) -> SaTokenResult<()> {
        self.session_repo.save_session_object(session).await
    }

    /// 保存账号 Session（指定 login_type）
    pub async fn save_session_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        session: &SaSession,
    ) -> SaTokenResult<()> {
        self.session_repo
            .save_account_session(login_type, login_id, session)
            .await
    }

    /// 删除账号 Session（默认 login_type）
    pub async fn delete_session(&self, login_id: &str) -> SaTokenResult<()> {
        self.session_repo
            .delete_account_session(LOGIN_TYPE_DEFAULT, login_id)
            .await
    }

    /// 删除账号 Session（指定 login_type）
    pub async fn delete_session_with_type(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<()> {
        self.session_repo
            .delete_account_session(login_type, login_id)
            .await
    }

    /// 获取指定账号的终端列表 | Terminal list of an account
    pub async fn get_terminal_list(
        &self,
        login_type: &str,
        login_id: &str,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<crate::session::SaTerminalInfo>> {
        let ns = self.account_ns(login_type, login_id);
        self.session_repo.get_terminal_list(&ns, device_type).await
    }

    /// 获取指定账号的 token 列表（来自终端列表）
    pub async fn get_token_value_list_by_login_id(
        &self,
        login_type: &str,
        login_id: &str,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<String>> {
        let ns = self.account_ns(login_type, login_id);
        self.session_repo.get_token_list(&ns, device_type).await
    }

    /// 按 token 反查终端信息 | Look up terminal info by token
    pub async fn get_terminal_info_by_token(
        &self,
        token: &TokenValue,
    ) -> SaTokenResult<Option<crate::session::SaTerminalInfo>> {
        let Ok(info) = self.get_token_info(token).await else {
            return Ok(None);
        };
        let ns = self.account_ns(&info.login_type, &info.login_id);
        self.session_repo.get_terminal(&ns, token.as_str()).await
    }

    // ---------- 权限 / 角色（全部委托 AuthzService）----------

    /// 获取权限列表（指定账号体系）| Permission list for a login type
    pub async fn get_permissions_with_type(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<String>> {
        self.authz_service
            .get_permissions(login_type, login_id)
            .await
    }

    /// 覆盖权限列表（指定账号体系）| Overwrite the permission list for a login type
    pub async fn set_permissions_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        permissions: Vec<String>,
    ) -> SaTokenResult<()> {
        self.authz_service
            .set_permissions(login_type, login_id, &permissions)
            .await
    }

    /// 追加单个权限（指定账号体系，B2-35 新增）
    /// Append one permission for a login type (added in B2-35).
    pub async fn add_permission_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        permission: String,
    ) -> SaTokenResult<()> {
        self.authz_service
            .add_permission(login_type, login_id, permission)
            .await
    }

    /// 移除单个权限（指定账号体系，B2-35 新增）
    /// Remove one permission for a login type (added in B2-35).
    pub async fn remove_permission_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        permission: &str,
    ) -> SaTokenResult<()> {
        self.authz_service
            .remove_permission(login_type, login_id, permission)
            .await
    }

    /// 清空权限（指定账号体系，B2-35 新增）
    /// Clear permissions for a login type (added in B2-35).
    pub async fn clear_permissions_with_type(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<()> {
        self.authz_service
            .clear_permissions(login_type, login_id)
            .await
    }

    /// 获取角色列表（指定账号体系）| Role list for a login type
    pub async fn get_roles_with_type(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<String>> {
        self.authz_service.get_roles(login_type, login_id).await
    }

    /// 覆盖角色列表（指定账号体系）| Overwrite the role list for a login type
    pub async fn set_roles_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        roles: Vec<String>,
    ) -> SaTokenResult<()> {
        self.authz_service
            .set_roles(login_type, login_id, &roles)
            .await
    }

    /// 追加单个角色（指定账号体系，B2-35 新增）
    /// Append one role for a login type (added in B2-35).
    pub async fn add_role_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        role: String,
    ) -> SaTokenResult<()> {
        self.authz_service
            .add_role(login_type, login_id, role)
            .await
    }

    /// 移除单个角色（指定账号体系，B2-35 新增）
    /// Remove one role for a login type (added in B2-35).
    pub async fn remove_role_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        role: &str,
    ) -> SaTokenResult<()> {
        self.authz_service
            .remove_role(login_type, login_id, role)
            .await
    }

    /// 清空角色（指定账号体系，B2-35 新增）
    /// Clear roles for a login type (added in B2-35).
    pub async fn clear_roles_with_type(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<()> {
        self.authz_service.clear_roles(login_type, login_id).await
    }

    // ---------- 默认账号体系的便捷包装 | Default login type convenience wrappers ----------

    /// 获取权限列表 | Permission list
    pub async fn get_permissions(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        self.get_permissions_with_type(LOGIN_TYPE_DEFAULT, login_id)
            .await
    }

    /// 覆盖权限列表 | Overwrite the permission list
    pub async fn set_permissions(
        &self,
        login_id: &str,
        permissions: Vec<String>,
    ) -> SaTokenResult<()> {
        self.set_permissions_with_type(LOGIN_TYPE_DEFAULT, login_id, permissions)
            .await
    }

    /// 追加单个权限 | Append one permission
    pub async fn add_permission(&self, login_id: &str, permission: String) -> SaTokenResult<()> {
        self.add_permission_with_type(LOGIN_TYPE_DEFAULT, login_id, permission)
            .await
    }

    /// 移除单个权限 | Remove one permission
    pub async fn remove_permission(&self, login_id: &str, permission: &str) -> SaTokenResult<()> {
        self.remove_permission_with_type(LOGIN_TYPE_DEFAULT, login_id, permission)
            .await
    }

    /// 清空权限 | Clear all permissions
    pub async fn clear_permissions(&self, login_id: &str) -> SaTokenResult<()> {
        self.clear_permissions_with_type(LOGIN_TYPE_DEFAULT, login_id)
            .await
    }

    /// 获取角色列表 | Role list
    pub async fn get_roles(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        self.get_roles_with_type(LOGIN_TYPE_DEFAULT, login_id).await
    }

    /// 覆盖角色列表 | Overwrite the role list
    pub async fn set_roles(&self, login_id: &str, roles: Vec<String>) -> SaTokenResult<()> {
        self.set_roles_with_type(LOGIN_TYPE_DEFAULT, login_id, roles)
            .await
    }

    /// 追加单个角色 | Append one role
    pub async fn add_role(&self, login_id: &str, role: String) -> SaTokenResult<()> {
        self.add_role_with_type(LOGIN_TYPE_DEFAULT, login_id, role)
            .await
    }

    /// 移除单个角色 | Remove one role
    pub async fn remove_role(&self, login_id: &str, role: &str) -> SaTokenResult<()> {
        self.remove_role_with_type(LOGIN_TYPE_DEFAULT, login_id, role)
            .await
    }

    /// 清空角色 | Clear all roles
    pub async fn clear_roles(&self, login_id: &str) -> SaTokenResult<()> {
        self.clear_roles_with_type(LOGIN_TYPE_DEFAULT, login_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LogoutMode, TokenStyle};
    use crate::error::SaTokenError;
    use chrono::{Duration, Utc};
    use sa_token_storage_memory::MemoryStorage;

    fn make_manager(is_concurrent: bool, auto_renew: bool, active_timeout: i64) -> SaTokenManager {
        let config = SaTokenConfig {
            timeout: 3600,
            token_style: TokenStyle::Uuid,
            is_concurrent,
            auto_renew,
            active_timeout,
            ..Default::default()
        };
        SaTokenManager::new(Arc::new(MemoryStorage::new()), config)
    }

    #[tokio::test]
    async fn test_non_concurrent_login_invalidates_previous_token() {
        let mgr = make_manager(false, false, -1);
        let t1 = mgr.login("user_1").await.unwrap();
        assert!(mgr.is_valid(&t1).await);
        let t2 = mgr.login("user_1").await.unwrap();
        assert!(!mgr.is_valid(&t1).await);
        assert!(mgr.is_valid(&t2).await);
    }

    #[tokio::test]
    async fn test_logout_clears_login_token_mapping() {
        let mgr = make_manager(true, false, -1);
        let token = mgr.login("user_1").await.unwrap();
        let map_key = mgr.keys().login_token("default", "user_1");
        assert!(mgr.storage.get(&map_key).await.unwrap().is_some());
        mgr.logout(&token).await.unwrap();
        assert!(mgr.storage.get(&map_key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_concurrent_login_appends_token_index() {
        let mgr = make_manager(true, false, -1);
        let t1 = mgr.login("user_1").await.unwrap();
        let t2 = mgr.login("user_1").await.unwrap();
        let list = mgr
            .token_repo()
            .list_tokens("default", "user_1")
            .await
            .unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&t1.as_str().to_string()));
        assert!(list.contains(&t2.as_str().to_string()));
    }

    #[tokio::test]
    async fn test_active_timeout_freeze_returns_inactive() {
        let mgr = make_manager(true, false, 1);
        let token = mgr.login("user_1").await.unwrap();
        let key = mgr.keys().token_info(token.as_str());
        let mut info = mgr.get_token_info(&token).await.unwrap();
        info.last_active_time = Utc::now() - Duration::seconds(10);
        mgr.storage
            .set(
                &key,
                &mgr.config.encode(&info).unwrap(),
                mgr.config.timeout_duration(),
            )
            .await
            .unwrap();
        let result = mgr.get_token_info(&token).await;
        assert!(matches!(result, Err(SaTokenError::TokenInactive)));
    }

    #[tokio::test]
    async fn test_auto_renew_updates_last_active_time() {
        // renew_threshold=-1：每次访问都续期；否则默认 300 对新 token 永不触发
        let config = SaTokenConfig {
            timeout: 3600,
            token_style: TokenStyle::Uuid,
            is_concurrent: true,
            auto_renew: true,
            active_timeout: 3600,
            renew_threshold: -1,
            ..Default::default()
        };
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), config);
        let token = mgr.login("user_1").await.unwrap();
        let before = mgr.get_token_info(&token).await.unwrap().last_active_time;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let after_info = mgr.get_token_info(&token).await.unwrap();
        assert!(
            after_info.last_active_time > before,
            "auto_renew must advance last_active_time"
        );
    }

    #[tokio::test]
    async fn test_auto_renew_skipped_when_remaining_above_threshold() {
        let config = SaTokenConfig {
            timeout: 3600,
            auto_renew: true,
            renew_threshold: 300,
            active_timeout: -1,
            token_style: TokenStyle::Uuid,
            ..Default::default()
        };
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), config);
        let token = mgr.login("user_skip").await.unwrap();
        let before = mgr.get_token_info(&token).await.unwrap().last_active_time;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let after = mgr.get_token_info(&token).await.unwrap().last_active_time;
        // remaining ~3600 > 300 → 不应续期
        assert_eq!(after, before);
    }

    #[tokio::test]
    async fn test_login_with_nonce_when_enabled() {
        let config = SaTokenConfig {
            enable_nonce: true,
            nonce_timeout: 60,
            auto_renew: false,
            ..Default::default()
        };
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), config);
        let nonce_mgr = crate::nonce::NonceManager::from_dao(mgr.dao().clone(), 60);
        let nonce = nonce_mgr.generate();
        let token = mgr
            .login_with_options("user_1", None, None, None, Some(nonce.clone()), None)
            .await
            .unwrap();
        assert!(mgr.is_valid(&token).await);
        let result = mgr
            .login_with_options("user_1", None, None, None, Some(nonce), None)
            .await;
        assert!(matches!(result, Err(SaTokenError::NonceAlreadyUsed)));
    }

    #[tokio::test]
    async fn test_kickout_token_returns_kicked_out() {
        let mgr = make_manager(true, false, -1);
        let token = mgr.login("user_kick").await.unwrap();
        mgr.kick_out_by_token(&token).await.unwrap();
        let err = mgr.get_token_info(&token).await.unwrap_err();
        assert!(matches!(err, SaTokenError::AccountKickedOut));
    }

    #[tokio::test]
    async fn test_replaced_token_returns_replaced() {
        let mgr = make_manager(false, false, -1);
        let t1 = mgr.login("user_rep").await.unwrap();
        let _t2 = mgr.login("user_rep").await.unwrap();
        let err = mgr.get_token_info(&t1).await.unwrap_err();
        assert!(matches!(err, SaTokenError::AccountReplaced));
    }

    #[tokio::test]
    async fn test_is_share_reuses_token() {
        let config = SaTokenConfig {
            is_share: true,
            is_concurrent: true,
            ..Default::default()
        };
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), config);
        let t1 = mgr.login("user_share").await.unwrap();
        let t2 = mgr.login("user_share").await.unwrap();
        assert_eq!(t1.as_str(), t2.as_str());
    }

    #[tokio::test]
    async fn test_max_login_count_overflow_kickout() {
        let config = SaTokenConfig {
            is_concurrent: true,
            max_login_count: 2,
            overflow_logout_mode: LogoutMode::KickOut,
            ..Default::default()
        };
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), config);
        let t1 = mgr.login("user_max").await.unwrap();
        let _t2 = mgr.login("user_max").await.unwrap();
        let t3 = mgr.login("user_max").await.unwrap();
        assert!(matches!(
            mgr.get_token_info(&t1).await,
            Err(SaTokenError::AccountKickedOut)
        ));
        assert!(mgr.is_valid(&t3).await);
    }

    #[test]
    fn test_account_ns_default_unchanged() {
        let mgr = make_manager(true, false, -1);
        assert_eq!(mgr.account_ns("default", "u1").as_str(), "u1");
        assert_eq!(mgr.account_ns("login", "u1").as_str(), "u1");
        assert_eq!(mgr.account_ns("", "u1").as_str(), "u1");
        assert_eq!(mgr.account_ns("admin", "u1").as_str(), "admin:u1");
    }

    #[tokio::test]
    async fn test_login_writes_terminal_and_logout_removes() {
        let mgr = make_manager(true, false, -1);
        let token = mgr
            .login_with_options("u1", None, Some("PC".to_string()), None, None, None)
            .await
            .unwrap();
        let terminals = mgr.get_terminal_list("default", "u1", None).await.unwrap();
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0].token_value, token.as_str());
        assert_eq!(terminals[0].device_type, "PC");
        assert_eq!(terminals[0].index, 1);

        mgr.logout(&token).await.unwrap();
        let terminals = mgr.get_terminal_list("default", "u1", None).await.unwrap();
        assert!(terminals.is_empty());
    }

    #[tokio::test]
    async fn test_terminal_filter_by_device_type() {
        let mgr = make_manager(true, false, -1);
        mgr.login_with_options("u1", None, Some("PC".to_string()), None, None, None)
            .await
            .unwrap();
        mgr.login_with_options("u1", None, Some("APP".to_string()), None, None, None)
            .await
            .unwrap();
        assert_eq!(
            mgr.get_terminal_list("default", "u1", Some("PC"))
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            mgr.get_token_value_list_by_login_id("default", "u1", None)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn test_permissions_isolated_by_login_type() {
        let mgr = make_manager(true, false, -1);
        mgr.set_permissions_with_type("admin", "u1", vec!["a:read".to_string()])
            .await
            .unwrap();
        mgr.set_permissions_with_type("user", "u1", vec!["u:read".to_string()])
            .await
            .unwrap();
        let admin_perms = mgr.get_permissions_with_type("admin", "u1").await.unwrap();
        let user_perms = mgr.get_permissions_with_type("user", "u1").await.unwrap();
        assert_eq!(admin_perms, vec!["a:read".to_string()]);
        assert_eq!(user_perms, vec!["u:read".to_string()]);
    }
}
