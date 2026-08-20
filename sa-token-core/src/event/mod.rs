// Author: 金书记
//
//! Event Listener Module | 事件监听模块
//!
//! Provides event listening capabilities for sa-token, supporting monitoring of login, logout, kick-out, and other operations.
//!
//! 提供 sa-token 的事件监听功能，支持监听登录、登出、踢出等操作。
//!
//! ## EventBus Code Flow Logic | EventBus 代码流程逻辑
//!
//! ### Overall Architecture | 整体架构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SaTokenEventBus                          │
//! │  ┌────────────────────────────────────────────────────┐    │
//! │  │  listeners: Arc<RwLock<Vec<Arc<dyn SaTokenListener>>>>  │
//! │  │  config: EventBusConfig                            │    │
//! │  │  - Stores all registered listeners                 │    │
//! │  │    存储所有注册的监听器                             │    │
//! │  │  - Uses RwLock for thread safety                   │    │
//! │  │    使用 RwLock 保证线程安全                        │    │
//! │  │  - Arc wrapping allows multi-thread sharing        │    │
//! │  │    Arc 包装允许多线程共享                          │    │
//! │  └────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Core Processes | 核心流程
//!
//! #### 1. Listener Registration Process | 监听器注册流程
//!
//! ```text
//! ┌──────────┐     ┌──────────────┐     ┌─────────────┐
//! │User Code │────▶│ register()   │────▶│Acquire Write│
//! │用户代码  │     │              │     │Lock 写锁获取│
//! └──────────┘     │ - Receive    │     │             │
//!                  │   listener   │     │ - Get lock  │
//!                  │   接收监听器  │     │   获取写锁   │
//!                  │ - Arc wrap   │     │ - Add to    │
//!                  │   Arc包装    │     │   list      │
//!                  └──────────────┘     │   添加到列表 │
//!                                       │ - Release   │
//!                                       │   释放写锁   │
//!                                       └─────────────┘
//!
//! Steps | 步骤：
//! 1. User creates custom listener instance
//!    用户创建自定义监听器实例
//! 2. Wrap listener with Arc::new()
//!    使用 Arc::new() 包装监听器
//! 3. Call event_bus.register(listener).await
//!    调用 event_bus.register(listener).await
//! 4. EventBus acquires write lock, adds listener to Vec
//!    EventBus 获取写锁，将监听器添加到 Vec 中
//! 5. Registration complete, waiting for event triggers
//!    监听器注册完成，等待事件触发
//! ```
//!
//! #### 2. Event Publishing Process (DispatchMode) | 事件发布流程 (分发模式)
//!
//! ```text
//! SaTokenManager::login OK
//!        │
//!        ▼
//!  event = SaTokenEvent::login(login_id, token)
//!        │
//!        ▼
//!  event_bus.publish(event)  ← dispatch by config.dispatch_mode
//!        │
//!        ├─[Sequential (default)]──── for each listener: spawn + timeout + await
//!        ├─[Concurrent]───────────── spawn all + timeout + join_all
//!        └─[Detached]─────────────── tokio::spawn, return immediately
//! ```
//!
//! ### Thread Safety Guarantees | 线程安全保证
//!
//! ```text
//! Arc<RwLock<Vec<Arc<dyn SaTokenListener>>>>
//!  │    │     │    │
//!  │    │     │    └─ Listener trait object | 监听器 trait 对象
//!  │    │     └────── Listener collection | 监听器集合
//!  │    └──────────── Read-write lock protection | 读写锁保护
//!  └───────────────── Cross-thread sharing | 跨线程共享
//!
//! - Arc: Allows EventBus to be shared across multiple Manager instances
//!        允许 EventBus 被多个 Manager 实例共享
//! - RwLock: Allows multiple readers to publish events concurrently, writer has exclusive registration
//!           允许多个读者同时发布事件，写者独占注册
//! - Inner Arc: Listeners can be shared across multiple EventBus instances
//!              监听器可以被多个 EventBus 共享
//! ```
//!
//! ## Usage Example | 使用示例
//!
//! ```rust,ignore
//! use sa_token_core::event::{SaTokenEvent, SaTokenListener, SaTokenEventBus};
//!
//! // Custom listener | 自定义监听器
//! struct MyListener;
//!
//! #[async_trait]
//! impl SaTokenListener for MyListener {
//!     async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
//!         println!("User {} logged in, token: {}", login_id, token);
//!         // 用户 {} 登录了，token: {}
//!     }
//!     
//!     async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
//!         println!("User {} logged out", login_id);
//!         // 用户 {} 登出了
//!     }
//! }
//!
//! // Register listener | 注册监听器
//! let event_bus = SaTokenEventBus::new();
//! event_bus.register(Arc::new(MyListener)).await;
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

/// 事件类型 | Event Type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SaTokenEventType {
    /// 登录事件 | Login event
    Login,
    /// 登出事件 | Logout event
    Logout,
    /// 踢出下线事件 | Kick out event
    KickOut,
    /// Token 续期事件 | Token renewal event
    RenewTimeout,
    /// 被顶下线事件（被其他设备登录）| Replaced by another login
    Replaced,
    /// 被封禁事件 | Banned event
    Banned,
    /// 解封事件 | Unbanned event
    Unbanned,
    /// 开启二级认证 | Open safe authentication
    OpenSafe,
    /// 关闭二级认证 | Close safe authentication
    CloseSafe,
    /// 二级认证校验通过 | Safe verification passed
    SafeVerify,
    /// 权限/角色数据变更 | Permission or role data changed
    ///
    /// 由 [`crate::service::AuthzService`] 的写操作触发。
    /// Emitted by write operations in `AuthzService`.
    GrantChanged,
}

/// 事件分发模式 | Event dispatch mode
///
/// 控制监听器的执行方式：顺序、并行、后台。
/// Controls how listeners are executed: sequential, concurrent, or background.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DispatchMode {
    /// 顺序执行，await 全部监听器（默认，兼容旧行为）
    ///
    /// Sequential execution, awaiting all listeners (default, compatible with old behavior).
    #[default]
    Sequential,
    /// 并行执行，await 全部监听器
    ///
    /// Concurrent execution, awaiting all listeners in parallel.
    Concurrent,
    /// 后台执行，不阻塞 publish 调用方返回
    ///
    /// Detached execution, does not block the publisher.
    Detached,
}

/// EventBus 运行时配置 | EventBus runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBusConfig {
    /// 分发模式 | Dispatch mode
    pub dispatch_mode: DispatchMode,
    /// 单个监听器最大执行时长；None 表示不限时
    ///
    /// Maximum execution time per listener; `None` means no timeout.
    pub listener_timeout: Option<Duration>,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            dispatch_mode: DispatchMode::Sequential,
            listener_timeout: Some(Duration::from_secs(5)),
        }
    }
}

impl EventBusConfig {
    /// 创建无超时限制的配置（用于向后兼容）
    ///
    /// Creates a config with no timeout (for backward compatibility).
    pub fn no_timeout() -> Self {
        Self {
            listener_timeout: None,
            ..Default::default()
        }
    }
}

/// 事件数据 | Event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaTokenEvent {
    /// 事件类型 | Event type
    pub event_type: SaTokenEventType,
    /// 登录ID | Login ID
    pub login_id: String,
    /// Token 值 | Token value
    pub token: String,
    /// 登录类型（如 "default", "admin" 等）| Login type (e.g. "default", "admin")
    pub login_type: String,
    /// 事件发生时间 | Event timestamp
    pub timestamp: DateTime<Utc>,
    /// 额外数据（用于扩展）| Extra data (for extension)
    pub extra: Option<serde_json::Value>,
}

impl SaTokenEvent {
    /// 创建登录事件 | Create login event
    pub fn login(login_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::Login,
            login_id: login_id.into(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: None,
        }
    }

    /// 创建登出事件 | Create logout event
    pub fn logout(login_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::Logout,
            login_id: login_id.into(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: None,
        }
    }

    /// 创建踢出下线事件 | Create kick out event
    pub fn kick_out(login_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::KickOut,
            login_id: login_id.into(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: None,
        }
    }

    /// 创建 Token 续期事件 | Create token renewal event
    ///
    /// # 参数 | Parameters
    /// - `login_id`: 登录 ID
    /// - `token`: Token 值
    /// - `timeout_seconds`: 续期后的有效时长（秒）| Renewed validity period (seconds)
    pub fn renew_timeout(
        login_id: impl Into<String>,
        token: impl Into<String>,
        timeout_seconds: i64,
    ) -> Self {
        Self {
            event_type: SaTokenEventType::RenewTimeout,
            login_id: login_id.into(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: Some(serde_json::json!({ "timeout_seconds": timeout_seconds })),
        }
    }

    /// 创建被顶下线事件 | Create replaced event
    pub fn replaced(login_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::Replaced,
            login_id: login_id.into(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: None,
        }
    }

    /// 创建被封禁事件 | Create banned event
    ///
    /// # 参数 | Parameters
    /// - `login_id`: 登录 ID
    /// - `service`: 封禁服务标识（如 "login", "comment"）| Service identifier
    /// - `level`: 封禁等级 | Ban level
    pub fn banned(login_id: impl Into<String>, service: impl Into<String>, level: i32) -> Self {
        Self {
            event_type: SaTokenEventType::Banned,
            login_id: login_id.into(),
            token: String::new(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: Some(serde_json::json!({ "service": service.into(), "level": level })),
        }
    }

    /// 创建解封事件 | Create unbanned event
    ///
    /// # 参数 | Parameters
    /// - `login_id`: 登录 ID
    /// - `service`: 解封服务标识 | Service identifier that was unbanned
    pub fn unbanned(login_id: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::Unbanned,
            login_id: login_id.into(),
            token: String::new(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: Some(serde_json::json!({ "service": service.into() })),
        }
    }

    /// 创建开启二级认证事件 | Create open safe event
    ///
    /// service 存入 extra 字段而非 login_type，避免语义混乱。
    /// Service stored in `extra` instead of `login_type` to avoid semantic confusion.
    pub fn open_safe(token: impl Into<String>, service: impl Into<String>) -> Self {
        let svc = service.into();
        Self {
            event_type: SaTokenEventType::OpenSafe,
            login_id: String::new(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: Some(serde_json::json!({ "service": svc })),
        }
    }

    /// 创建关闭二级认证事件 | Create close safe event
    pub fn close_safe(token: impl Into<String>, service: impl Into<String>) -> Self {
        let svc = service.into();
        Self {
            event_type: SaTokenEventType::CloseSafe,
            login_id: String::new(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: Some(serde_json::json!({ "service": svc })),
        }
    }

    /// 创建二级认证校验通过事件 | Create safe verification passed event
    pub fn safe_verify(token: impl Into<String>, service: impl Into<String>) -> Self {
        let svc = service.into();
        Self {
            event_type: SaTokenEventType::SafeVerify,
            login_id: String::new(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: Some(serde_json::json!({ "service": svc })),
        }
    }

    /// 创建权限/角色变更事件 | Create grant changed event
    pub fn grant_changed(login_id: impl Into<String>, login_type: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::GrantChanged,
            login_id: login_id.into(),
            token: String::new(),
            login_type: login_type.into(),
            timestamp: Utc::now(),
            extra: None,
        }
    }

    /// 设置登录类型 | Set login type
    pub fn with_login_type(mut self, login_type: impl Into<String>) -> Self {
        self.login_type = login_type.into();
        self
    }

    /// 设置额外数据 | Set extra data
    pub fn with_extra(mut self, extra: serde_json::Value) -> Self {
        self.extra = Some(extra);
        self
    }
}

/// 事件监听器 trait | Event Listener Trait
///
/// 实现此 trait 来自定义事件处理逻辑
/// Implement this trait to customize event handling logic
///
/// # 使用示例 | Usage Example
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use sa_token_core::SaTokenListener;
///
/// struct MyListener;
///
/// #[async_trait]
/// impl SaTokenListener for MyListener {
///     async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
///         // 自定义登录处理 | Custom login handling
///         println!("User {} logged in", login_id);
///     }
/// }
/// ```
#[async_trait]
pub trait SaTokenListener: Send + Sync {
    /// 登录事件 | Login Event
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }

    /// 登出事件 | Logout Event
    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }

    /// 踢出下线事件 | Kick Out Event
    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }

    /// Token 续期事件 | Token Renewal Event
    ///
    /// # 参数 | Parameters
    /// - `login_id`: 登录 ID | Login ID
    /// - `token`: Token 值 | Token value
    /// - `login_type`: 登录类型 | Login type
    /// - `timeout_seconds`: 续期后的有效时长（秒）| Renewed validity period (seconds)
    async fn on_renew_timeout(
        &self,
        login_id: &str,
        token: &str,
        login_type: &str,
        timeout_seconds: i64,
    ) {
        let _ = (login_id, token, login_type, timeout_seconds);
    }

    /// 被顶下线事件 | Replaced Event
    async fn on_replaced(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }

    /// 被封禁事件 | Banned Event
    async fn on_banned(&self, login_id: &str, login_type: &str) {
        let _ = (login_id, login_type);
    }

    /// 解封事件 | Unbanned Event
    ///
    /// # 参数 | Parameters
    /// - `login_id`: 登录 ID | Login ID
    /// - `service`: 解封的服务标识 | Service identifier that was unbanned
    /// - `login_type`: 登录类型 | Login type
    async fn on_unbanned(&self, login_id: &str, service: &str, login_type: &str) {
        let _ = (login_id, service, login_type);
    }

    /// 开启二级认证 | Open Safe Authentication
    async fn on_open_safe(&self, token: &str, service: &str) {
        let _ = (token, service);
    }

    /// 关闭二级认证 | Close Safe Authentication
    async fn on_close_safe(&self, token: &str, service: &str) {
        let _ = (token, service);
    }

    /// 二级认证校验通过 | Safe Verification Passed
    ///
    /// # 参数 | Parameters
    /// - `token`: Token 值 | Token value
    /// - `service`: 业务标识 | Service identifier
    async fn on_safe_verify(&self, token: &str, service: &str) {
        let _ = (token, service);
    }

    /// 权限/角色变更事件 | Grant Changed Event
    async fn on_grant_changed(&self, login_id: &str, login_type: &str) {
        let _ = (login_id, login_type);
    }

    /// 通用事件处理（所有事件都会触发此方法）
    /// Generic Event Handler (triggered by all events)
    async fn on_event(&self, event: &SaTokenEvent) {
        let _ = event;
    }
}

/// Listener list snapshot type for publish (Arc clone of Arc<Vec>).
/// publish 用的监听器快照类型（对 Arc<Vec> 做 Arc clone）。
type ListenerList = Arc<Vec<Arc<dyn SaTokenListener>>>;

/// 事件总线 - 管理所有监听器并分发事件
///
/// Event bus - manages all listeners and dispatches events.
///
/// 列表用内层 `Arc<Vec>` 做 publish 快照；配置保持值字段。
/// Inner `Arc<Vec>` makes publish a pointer snapshot; config stays a value field.
#[derive(Clone)]
pub struct SaTokenEventBus {
    listeners: Arc<RwLock<ListenerList>>,
    config: EventBusConfig,
}

impl std::fmt::Debug for SaTokenEventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SaTokenEventBus { .. }")
    }
}

impl SaTokenEventBus {
    /// 创建新的事件总线（默认配置）
    ///
    /// Creates a new event bus with default configuration.
    pub fn new() -> Self {
        Self::with_config(EventBusConfig::default())
    }

    /// 创建事件总线（自定义配置）
    ///
    /// Creates an event bus with custom configuration.
    pub fn with_config(config: EventBusConfig) -> Self {
        Self {
            listeners: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            config,
        }
    }

    /// 获取配置引用 | Get configuration reference
    pub fn config(&self) -> &EventBusConfig {
        &self.config
    }

    /// poison 时 into_inner 恢复，单个 listener unwind 不能卡住整条总线。
    /// Recover from a poisoned lock so one unwind cannot jam the bus.
    fn read_guard(&self) -> std::sync::RwLockReadGuard<'_, Arc<Vec<Arc<dyn SaTokenListener>>>> {
        self.listeners.read().unwrap_or_else(|poisoned| {
            tracing::warn!("EventBus RwLock poisoned, recovering");
            poisoned.into_inner()
        })
    }

    fn write_guard(&self) -> std::sync::RwLockWriteGuard<'_, Arc<Vec<Arc<dyn SaTokenListener>>>> {
        self.listeners.write().unwrap_or_else(|poisoned| {
            tracing::warn!("EventBus RwLock poisoned during write, recovering");
            poisoned.into_inner()
        })
    }

    /// 热路径：拷贝表指针后立即放锁，供后续 await 使用。
    /// Hot path: clone the table pointer then drop the lock before any `.await`.
    fn snapshot(&self) -> Arc<Vec<Arc<dyn SaTokenListener>>> {
        Arc::clone(&*self.read_guard())
    }

    /// 注册监听器 | Registers a listener.
    pub fn register(&self, listener: Arc<dyn SaTokenListener>) {
        let mut guard = self.write_guard();
        let mut next = Vec::with_capacity(guard.len() + 1);
        next.extend(guard.iter().cloned());
        next.push(listener);
        *guard = Arc::new(next);
    }

    /// 异步注册监听器（为了保持 API 兼容性）
    ///
    /// Registers a listener asynchronously (for API compatibility).
    pub async fn register_async(&self, listener: Arc<dyn SaTokenListener>) {
        self.register(listener);
    }

    /// 移除所有监听器 | Clears all listeners.
    pub fn clear(&self) {
        *self.write_guard() = Arc::new(Vec::new());
    }

    /// 只读长度。Arc&lt;Vec&gt; Deref 到 Vec，不必为 count 克隆表。
    /// Read `len` via Deref; never clone the vec just to count.
    pub fn listener_count(&self) -> usize {
        self.read_guard().len()
    }

    /// 发布事件（按 DispatchMode 分发）
    ///
    /// Publishes an event (dispatches according to DispatchMode).
    pub async fn publish(&self, event: SaTokenEvent) {
        match self.config.dispatch_mode {
            DispatchMode::Sequential => {
                self.dispatch_sequential(event).await;
            }
            DispatchMode::Concurrent => {
                self.dispatch_concurrent(event).await;
            }
            DispatchMode::Detached => {
                let bus = self.clone();
                tokio::spawn(async move {
                    bus.dispatch_sequential(event).await;
                });
            }
        }
    }

    /// 顺序分发（超时 + panic 隔离）
    ///
    /// Sequential dispatch (timeout + panic isolation).
    async fn dispatch_sequential(&self, event: SaTokenEvent) {
        let listeners = self.snapshot();
        let timeout = self.config.listener_timeout;
        for listener in listeners.iter() {
            Self::invoke_listener_safe(Arc::clone(listener), &event, timeout).await;
        }
    }

    /// 并行分发（检查 JoinError）
    ///
    /// Concurrent dispatch (checks JoinError).
    async fn dispatch_concurrent(&self, event: SaTokenEvent) {
        let listeners = self.snapshot();
        let timeout = self.config.listener_timeout;
        let mut handles = Vec::with_capacity(listeners.len());

        for listener in listeners.iter() {
            let listener = Arc::clone(listener);
            let ev = event.clone();
            let handle = tokio::spawn(async move {
                Self::invoke_listener_safe(listener, &ev, timeout).await;
            });
            handles.push(handle);
        }

        for (idx, handle) in handles.into_iter().enumerate() {
            if let Err(e) = handle.await {
                if e.is_panic() {
                    tracing::warn!(
                        listener_idx = idx,
                        "listener task panicked in concurrent mode"
                    );
                } else {
                    tracing::warn!(listener_idx = idx, "listener task cancelled");
                }
            }
        }
    }

    /// 单监听器安全调用（spawn 隔离 panic + timeout 保护）
    ///
    /// Safe invocation of a single listener (spawn isolates panic + timeout).
    async fn invoke_listener_safe(
        listener: Arc<dyn SaTokenListener>,
        event: &SaTokenEvent,
        timeout: Option<Duration>,
    ) {
        let event_owned = event.clone();
        let handle = tokio::spawn(async move {
            let fut = Self::dispatch_to_listener(&listener, &event_owned);
            match timeout {
                Some(d) => match tokio::time::timeout(d, fut).await {
                    Ok(()) => Ok(()),
                    Err(_elapsed) => Err("timeout"),
                },
                None => {
                    fut.await;
                    Ok(())
                }
            }
        });

        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err("timeout")) => {
                tracing::warn!(
                    event_type = ?event.event_type,
                    "listener timed out during event dispatch"
                );
            }
            Ok(Err(_)) => {}
            Err(e) if e.is_panic() => {
                tracing::warn!(
                    event_type = ?event.event_type,
                    "listener panicked during event dispatch"
                );
            }
            Err(e) => {
                tracing::warn!("listener task cancelled: {:?}", e);
            }
        }
    }

    /// 分发事件到单个监听器（on_event + typed 方法）
    ///
    /// Dispatches an event to a single listener (on_event + typed method).
    async fn dispatch_to_listener(listener: &Arc<dyn SaTokenListener>, event: &SaTokenEvent) {
        listener.on_event(event).await;

        match event.event_type {
            SaTokenEventType::Login => {
                listener
                    .on_login(&event.login_id, &event.token, &event.login_type)
                    .await;
            }
            SaTokenEventType::Logout => {
                listener
                    .on_logout(&event.login_id, &event.token, &event.login_type)
                    .await;
            }
            SaTokenEventType::KickOut => {
                listener
                    .on_kick_out(&event.login_id, &event.token, &event.login_type)
                    .await;
            }
            SaTokenEventType::RenewTimeout => {
                let timeout_seconds = event
                    .extra
                    .as_ref()
                    .and_then(|v| v.get("timeout_seconds"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                listener
                    .on_renew_timeout(
                        &event.login_id,
                        &event.token,
                        &event.login_type,
                        timeout_seconds,
                    )
                    .await;
            }
            SaTokenEventType::Replaced => {
                listener
                    .on_replaced(&event.login_id, &event.token, &event.login_type)
                    .await;
            }
            SaTokenEventType::Banned => {
                listener.on_banned(&event.login_id, &event.login_type).await;
            }
            SaTokenEventType::Unbanned => {
                let service = event
                    .extra
                    .as_ref()
                    .and_then(|v| v.get("service"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                listener
                    .on_unbanned(&event.login_id, service, &event.login_type)
                    .await;
            }
            SaTokenEventType::OpenSafe => {
                let service = event
                    .extra
                    .as_ref()
                    .and_then(|v| v.get("service"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&event.login_type);
                listener.on_open_safe(&event.token, service).await;
            }
            SaTokenEventType::CloseSafe => {
                let service = event
                    .extra
                    .as_ref()
                    .and_then(|v| v.get("service"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&event.login_type);
                listener.on_close_safe(&event.token, service).await;
            }
            SaTokenEventType::SafeVerify => {
                let service = event
                    .extra
                    .as_ref()
                    .and_then(|v| v.get("service"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                listener.on_safe_verify(&event.token, service).await;
            }
            SaTokenEventType::GrantChanged => {
                listener
                    .on_grant_changed(&event.login_id, &event.login_type)
                    .await;
            }
        }
    }
}

impl Default for SaTokenEventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// 简单的日志监听器示例 | Simple logging listener example
pub struct LoggingListener;

#[async_trait]
impl SaTokenListener for LoggingListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        tracing::info!(
            login_id = %login_id,
            token = %token,
            login_type = %login_type,
            "用户登录"
        );
    }

    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        tracing::info!(
            login_id = %login_id,
            token = %token,
            login_type = %login_type,
            "用户登出"
        );
    }

    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {
        tracing::warn!(
            login_id = %login_id,
            token = %token,
            login_type = %login_type,
            "用户被踢出下线"
        );
    }

    async fn on_renew_timeout(
        &self,
        login_id: &str,
        token: &str,
        login_type: &str,
        timeout_seconds: i64,
    ) {
        tracing::debug!(
            login_id = %login_id,
            token = %token,
            login_type = %login_type,
            timeout_seconds = timeout_seconds,
            "Token 续期"
        );
    }

    async fn on_replaced(&self, login_id: &str, token: &str, login_type: &str) {
        tracing::warn!(
            login_id = %login_id,
            token = %token,
            login_type = %login_type,
            "用户被顶下线"
        );
    }

    async fn on_banned(&self, login_id: &str, login_type: &str) {
        tracing::warn!(
            login_id = %login_id,
            login_type = %login_type,
            "用户被封禁"
        );
    }

    async fn on_unbanned(&self, login_id: &str, service: &str, login_type: &str) {
        tracing::info!(
            login_id = %login_id,
            service = %service,
            login_type = %login_type,
            "用户被解封"
        );
    }

    async fn on_safe_verify(&self, token: &str, service: &str) {
        tracing::debug!(
            token = %token,
            service = %service,
            "二级认证校验通过"
        );
    }
}

impl std::fmt::Debug for LoggingListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoggingListener { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestListener {
        login_count: Arc<RwLock<i32>>,
    }

    impl TestListener {
        fn new() -> Self {
            Self {
                login_count: Arc::new(RwLock::new(0)),
            }
        }
    }

    #[async_trait]
    impl SaTokenListener for TestListener {
        async fn on_login(&self, _login_id: &str, _token: &str, _login_type: &str) {
            let mut count = self.login_count.write().unwrap();
            *count += 1;
        }
    }

    #[tokio::test]
    async fn test_event_bus() {
        let bus = SaTokenEventBus::with_config(EventBusConfig::no_timeout());
        let listener = Arc::new(TestListener::new());
        let login_count = Arc::clone(&listener.login_count);

        bus.register(listener);

        let event = SaTokenEvent::login("user_123", "token_abc");
        bus.publish(event).await;

        let count = login_count.read().unwrap();
        assert_eq!(*count, 1);
    }

    #[test]
    fn test_event_creation() {
        let event = SaTokenEvent::login("user_123", "token_abc");
        assert_eq!(event.event_type, SaTokenEventType::Login);
        assert_eq!(event.login_id, "user_123");
        assert_eq!(event.token, "token_abc");
    }
}
