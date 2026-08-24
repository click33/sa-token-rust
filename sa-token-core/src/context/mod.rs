// Author: 金书记 | Author: Jin Shuji
//
//! Request Context | 请求上下文
//!
//! ## 存储策略 | Storage Strategy
//!
//! - **`tokio::task_local!`**（主路径 | primary path）：跨 `await`、跨 Tokio worker 仍与同一异步任务绑定；
//!   值为 `SaTokenContext`（内部 `Arc<RwLock<Inner>>`），**scope 内可突变**（`switch_to`）。
//! - **`thread_local`**（兜底 | fallback）：无 Tokio runtime 或纯同步测试路径；
//!   行为与主路径 API 一致，但**不跨 spawn 继承**。
//!
//! ## 读取优先级 | Read Priority
//!
//! `try_current()`：**task-local 优先**，再回落 thread-local。
//!
//! ## 可变性设计（B3 核心修复）| Mutability Design (B3 core fix)
//!
//! **问题**：旧版 `SaTokenContext` 是 flat struct，`switch_to` 无法修改 `TASK_CTX.scope` 内的副本。
//!
//! **解决**：改为 `Arc<RwLock<Inner>>`，Clone 时共享句柄，`with_current_mut` 就地突变。
//!
//! ## 与 GrantScope 协调（B2 特性）| Coordination with GrantScope (B2 feature)
//!
//! `SaTokenContext::scope` 同时建立 token 上下文 + 授权快照（`TASK_GRANTS`），一次调用完成两者绑定。

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, RwLock};

use crate::token::{TokenInfo, TokenValue};

/// 上下文可变状态（内部数据，由 `Arc<RwLock>` 保护）
///
/// Mutable context state (internal data protected by `Arc<RwLock>`).
///
/// 字段 public：允许 `with_current_mut` 闭包内直接修改。
/// Fields public: allows direct mutation inside `with_current_mut` closures.
#[derive(Debug, Default)]
pub struct SaTokenContextInner {
    /// 当前请求的 token | Current request's token
    pub token: Option<TokenValue>,

    /// 当前请求的 token 信息 | Current request's token info
    pub token_info: Option<Arc<TokenInfo>>,

    /// 登录 ID（来自 token 解析）| Login ID (parsed from token)
    pub login_id: Option<String>,

    /// 身份临时切换目标 login_id（运行时动态设置，对应 `StpUtil::switch_to`）
    ///
    /// Temporary identity switch target (set dynamically via `StpUtil::switch_to`).
    pub switch_login_id: Option<String>,

    /// Headers needed by HTTP Basic / Same-Token macros.
    /// HTTP Basic / Same-Token 宏所需的请求头快照。
    pub auth_meta: RequestAuthMeta,
}

/// Headers needed by HTTP Basic / Same-Token macros (copied before `.await`).
/// HTTP Basic / Same-Token 宏所需的请求头（在 `.await` 前拷贝）。
#[derive(Debug, Clone, Default)]
pub struct RequestAuthMeta {
    /// Raw `Authorization` header (may be `Basic ...` or `Bearer ...`).
    /// 原始 `Authorization` 头。
    pub authorization: Option<String>,
    /// Same-Token header value (header name from config).
    /// Same-Token 头的值（头名来自配置）。
    pub same_token: Option<String>,
}

impl RequestAuthMeta {
    /// Capture from any `SaRequest`. Header lookup is adapter-defined.
    /// 从任意 `SaRequest` 捕获。头查找语义由适配器决定。
    pub fn from_request<R: sa_token_adapter::context::SaRequest>(
        req: &R,
        same_token_header: &str,
    ) -> Self {
        let authorization = req
            .get_header("Authorization")
            .or_else(|| req.get_header("authorization"));
        let same_token = req.get_header(same_token_header).or_else(|| {
            if same_token_header.eq_ignore_ascii_case("SA-SAME-TOKEN") {
                req.get_header("sa-same-token")
            } else {
                None
            }
        });
        Self {
            authorization,
            same_token,
        }
    }
}

thread_local! {
    /// 同步兜底：仅在本 OS 线程可见，不跨 `tokio::spawn`
    ///
    /// Sync fallback: visible only within the current OS thread, does not cross `tokio::spawn`.
    static TLS_CTX: RefCell<Option<SaTokenContext>> = const { RefCell::new(None) };

    /// 请求级授权快照（thread-local 兜底，与 TASK_GRANTS 平行）
    ///
    /// Request-scoped authorization snapshot (thread-local fallback, parallel to TASK_GRANTS).
    static TLS_GRANTS: RefCell<Option<GrantScope>> = const { RefCell::new(None) };
}

tokio::task_local! {
    /// 异步主路径：与逻辑任务绑定，跨 await 有效
    ///
    /// Async primary path: bound to the logical task, survives across awaits.
    static TASK_CTX: SaTokenContext;

    /// 请求级授权快照（task-local 主路径，B2 特性）
    ///
    /// Request-scoped authorization snapshot (task-local primary, B2 feature).
    static TASK_GRANTS: GrantScope;
}

/// 请求级授权快照（B2 特性，与 `SaTokenContext` 平行存储）
///
/// Request-scoped authorization snapshot (B2 feature, stored in parallel with `SaTokenContext`).
///
/// 内部用 `Arc<RwLock<HashMap>>`：[`SaTokenContext::current_grant_scope`] 返回的是
/// **克隆**，但克隆共享同一份数据，因此在请求任意位置写入都能被后续读取看到。
///
/// Backed by `Arc<RwLock<HashMap>>`: `current_grant_scope` hands out clones that
/// share one map, so a write anywhere in the request is visible to later reads.
#[derive(Debug, Clone, Default)]
pub struct GrantScope {
    entries: Arc<RwLock<HashMap<String, Arc<[String]>>>>,
}

impl GrantScope {
    /// 创建空快照 | Create an empty snapshot
    pub fn new() -> Self {
        Self::default()
    }

    /// 读取快照项 | Read an entry
    pub fn get(&self, key: &str) -> Option<Arc<[String]>> {
        let guard = self.entries.read().ok()?;
        guard.get(key).map(Arc::clone)
    }

    /// 写入快照项 | Store an entry
    pub fn put(&self, key: String, value: Arc<[String]>) {
        if let Ok(mut guard) = self.entries.write() {
            guard.insert(key, value);
        }
    }

    /// 移除快照项（权限写操作后调用，使请求立即看到新值）
    ///
    /// Remove an entry after a write so the request sees the new value at once.
    pub fn remove(&self, key: &str) {
        if let Ok(mut guard) = self.entries.write() {
            guard.remove(key);
        }
    }

    /// 清空快照 | Clear the snapshot
    pub fn clear(&self) {
        if let Ok(mut guard) = self.entries.write() {
            guard.clear();
        }
    }

    /// 在给定 `Future` 期间挂载本快照（独立 API，兼容 B2）
    ///
    /// Mounts this snapshot for the duration of a future (standalone API, B2 compat).
    ///
    /// 优先使用 `SaTokenContext::scope`（正常 Web 请求同时需要 token + grant）。
    /// Prefer `SaTokenContext::scope` for normal Web requests needing both token and grant.
    pub async fn run<F, T>(scope: Self, future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        TASK_GRANTS.scope(scope, future).await
    }
}

/// 请求上下文句柄：`Clone` 共享同一 `Inner`，突变对所有克隆可见
///
/// Request context handle: `Clone` shares the same `Inner`; mutations are visible to all clones.
///
/// 字段私有（`inner: Arc<RwLock<...>>`）：强制走 builder / accessor API。
/// Fields private: forces use of builder/accessor API.
#[derive(Clone)]
pub struct SaTokenContext {
    inner: Arc<RwLock<SaTokenContextInner>>,
}

impl std::fmt::Debug for SaTokenContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.read() {
            Ok(guard) => f
                .debug_struct("SaTokenContext")
                .field("inner", &*guard)
                .finish(),
            Err(_) => f
                .debug_struct("SaTokenContext")
                .field("inner", &"<poisoned>")
                .finish(),
        }
    }
}

impl SaTokenContext {
    /// 创建空上下文 | Create an empty context
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(SaTokenContextInner::default())),
        }
    }

    /// 链式 builder 入口（替代旧版 struct literal 字段赋值）
    ///
    /// Fluent builder entry (replaces old struct literal field assignment).
    pub fn builder() -> SaTokenContextBuilder {
        SaTokenContextBuilder::new()
    }

    // ==================== 字段 Accessor ====================

    /// 读取 token（快照）| Read token (snapshot)
    pub fn token(&self) -> Option<TokenValue> {
        Self::read_inner(&self.inner).token.clone()
    }

    /// 读取 token_info（快照）| Read token_info (snapshot)
    pub fn token_info(&self) -> Option<Arc<TokenInfo>> {
        Self::read_inner(&self.inner).token_info.clone()
    }

    /// 读取 login_id（快照）| Read login_id (snapshot)
    pub fn login_id(&self) -> Option<String> {
        Self::read_inner(&self.inner).login_id.clone()
    }

    /// 读取 switch_login_id（快照）| Read switch_login_id (snapshot)
    pub fn switch_login_id(&self) -> Option<String> {
        Self::read_inner(&self.inner).switch_login_id.clone()
    }

    /// Snapshot of captured auth headers.
    /// 已捕获鉴权头的快照。
    pub fn auth_meta(&self) -> RequestAuthMeta {
        Self::read_inner(&self.inner).auth_meta.clone()
    }

    // ==================== Scope 与 Task-Local 管理 ====================

    /// 在 `fut` 全生命周期内绑定本上下文（跨 await / 跨 worker 仍有效），
    /// **同时**建立一份请求级授权快照（B2 特性）。
    ///
    /// Binds this context for the whole lifetime of `fut` (survives across awaits/workers),
    /// and simultaneously establishes a request-scoped authorization snapshot (B2 feature).
    pub async fn scope<F, R>(ctx: SaTokenContext, fut: F) -> R
    where
        F: Future<Output = R>,
    {
        TASK_CTX
            .scope(ctx, TASK_GRANTS.scope(GrantScope::new(), fut))
            .await
    }

    /// 当前上下文副本：**task-local 优先**，再回落 thread-local
    ///
    /// Current context clone: **task-local first**, then fallback to thread-local.
    pub fn try_current() -> Option<SaTokenContext> {
        match TASK_CTX.try_with(|c| c.clone()) {
            Ok(c) => Some(c),
            Err(_) => TLS_CTX.with(|c| c.borrow().clone()),
        }
    }

    /// 获取当前上下文（`try_current` 别名）
    ///
    /// Get current context (`try_current` alias).
    pub fn get_current() -> Option<SaTokenContext> {
        Self::try_current()
    }

    /// 设置当前上下文（thread-local 兜底路径，同时建立授权快照）
    ///
    /// Set current context (thread-local fallback path; also establishes authz snapshot).
    ///
    /// **scope 内**调用时会合并字段到现有句柄（不替换 Arc）；
    /// **scope 外**直接替换 thread-local 存储。
    ///
    /// Inside scope: merges fields into existing handle (does not replace Arc).
    /// Outside scope: replaces thread-local storage.
    pub fn set_current(ctx: SaTokenContext) {
        if TASK_CTX.try_with(|_| ()).is_ok() {
            let _ = Self::with_current_mut(|inner| {
                let snap = Self::read_inner(&ctx.inner);
                inner.token.clone_from(&snap.token);
                inner.token_info.clone_from(&snap.token_info);
                inner.login_id.clone_from(&snap.login_id);
                inner.switch_login_id.clone_from(&snap.switch_login_id);
                inner.auth_meta = snap.auth_meta.clone();
            });
            return;
        }
        TLS_CTX.with(|c| {
            *c.borrow_mut() = Some(ctx);
        });
        TLS_GRANTS.with(|g| {
            *g.borrow_mut() = Some(GrantScope::new());
        });
    }

    /// 清除当前上下文与授权快照（thread-local 兜底；task-local 随 scope 结束自动 drop）
    ///
    /// Clear current context and authz snapshot (thread-local fallback; task-local auto-drops when scope ends).
    pub fn clear() {
        TLS_CTX.with(|c| {
            *c.borrow_mut() = None;
        });
        TLS_GRANTS.with(|g| {
            *g.borrow_mut() = None;
        });
    }

    /// **单轨突变入口**：优先修改 task-local 共享 Inner，否则修改 thread-local（修复 B3-1/2）
    ///
    /// **Single-track mutation entry**: mutates task-local shared `Inner` first, else thread-local (fixes B3-1/2).
    ///
    /// **死锁警告**：禁止在闭包 `f` 内调用 `try_current()` 等读上下文方法！
    ///
    /// **Deadlock warning**: DO NOT call `try_current()` or other context-reading methods inside `f`!
    pub fn with_current_mut<F, R>(f: F) -> Option<R>
    where
        F: FnOnce(&mut SaTokenContextInner) -> R,
    {
        if let Ok(handle) = TASK_CTX.try_with(|c| c.clone()) {
            let mut guard = Self::write_inner(&handle.inner);
            return Some(f(&mut guard));
        }

        TLS_CTX.with(|cell| {
            let mut opt = cell.borrow_mut();
            if opt.is_none() {
                let auto_create = crate::util::StpUtil::try_get_config()
                    .map(|c| c.context_auto_create)
                    .unwrap_or(false);
                if !auto_create {
                    return None;
                }
                *opt = Some(SaTokenContext::new());
            }
            let handle = opt.as_ref()?;
            let mut guard = Self::write_inner(&handle.inner);
            Some(f(&mut guard))
        })
    }

    /// 当前请求的授权快照；**优先 task-local**，再回落 thread-local（B2 特性）
    ///
    /// The current request's authorization snapshot; task-local first with a thread-local fallback (B2 feature).
    pub fn current_grant_scope() -> Option<GrantScope> {
        match TASK_GRANTS.try_with(|s| s.clone()) {
            Ok(s) => Some(s),
            Err(_) => TLS_GRANTS.with(|s| s.borrow().clone()),
        }
    }

    /// 当前请求的账号体系（login_type）；无上下文或字段为空时返回 `None`
    ///
    /// The current request's login type; `None` when absent or empty.
    pub fn current_login_type() -> Option<String> {
        Self::try_current()
            .and_then(|ctx| ctx.token_info())
            .map(|info| info.login_type.to_string())
            .filter(|lt| !lt.is_empty())
    }

    // ==================== RwLock Poison Recovery ====================

    /// 无 poison 语义的读锁（panic 后自动恢复内部数据）
    ///
    /// Poison-free read lock (recovers inner data after panic).
    fn read_inner(
        inner: &Arc<RwLock<SaTokenContextInner>>,
    ) -> std::sync::RwLockReadGuard<'_, SaTokenContextInner> {
        inner.read().unwrap_or_else(|e| e.into_inner())
    }

    /// 无 poison 语义的写锁
    ///
    /// Poison-free write lock.
    fn write_inner(
        inner: &Arc<RwLock<SaTokenContextInner>>,
    ) -> std::sync::RwLockWriteGuard<'_, SaTokenContextInner> {
        inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for SaTokenContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder：供 router / 测试 / 插件构造上下文，避免公开 `inner` 字段
///
/// Builder: for router/tests/plugins to construct context without exposing `inner` field.
pub struct SaTokenContextBuilder {
    inner: SaTokenContextInner,
}

impl std::fmt::Debug for SaTokenContextBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SaTokenContextBuilder { .. }")
    }
}

impl SaTokenContextBuilder {
    /// 创建空 builder | Create empty builder
    pub fn new() -> Self {
        Self {
            inner: SaTokenContextInner::default(),
        }
    }

    /// 设置 token | Set token
    pub fn token(mut self, token: TokenValue) -> Self {
        self.inner.token = Some(token);
        self
    }

    /// 设置 token_info | Set token_info
    pub fn token_info(mut self, info: Arc<TokenInfo>) -> Self {
        self.inner.token_info = Some(info);
        self
    }

    /// 设置 login_id | Set login_id
    pub fn login_id(mut self, login_id: impl Into<String>) -> Self {
        self.inner.login_id = Some(login_id.into());
        self
    }

    /// 设置 switch_login_id（**仅测试用**，生产环境用 `StpUtil::switch_to` 运行时切换）
    ///
    /// Set switch_login_id (**test-only**; use `StpUtil::switch_to` for runtime switching in production).
    pub fn switch_login_id(mut self, login_id: impl Into<String>) -> Self {
        self.inner.switch_login_id = Some(login_id.into());
        self
    }

    /// Set captured auth headers | 设置已捕获的鉴权头
    pub fn auth_meta(mut self, meta: RequestAuthMeta) -> Self {
        self.inner.auth_meta = meta;
        self
    }

    /// 构建 `SaTokenContext`（消耗 builder）
    ///
    /// Build `SaTokenContext` (consumes builder).
    pub fn build(self) -> SaTokenContext {
        SaTokenContext {
            inner: Arc::new(RwLock::new(self.inner)),
        }
    }
}

impl Default for SaTokenContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}
