//! Distributed Session Management Module | 分布式 Session 管理模块
//!
//! # Overview | 概述
//!
//! This module enables **distributed session management** for microservices architecture,
//! allowing multiple services to share authentication sessions seamlessly.
//! 本模块为微服务架构提供**分布式 Session 管理**，允许多个服务无缝共享认证会话。
//!
//! ## Architecture Context | 架构上下文
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────┐
//! │                   Microservices Architecture                       │
//! │                   微服务架构                                        │
//! └────────────────────────────────────────────────────────────────────┘
//!
//!    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
//!    │  Service A   │  │  Service B   │  │  Service C   │
//!    │  (User API)  │  │  (Order API) │  │  (Pay API)   │
//!    └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
//!           │                  │                  │
//!           └──────────────────┼──────────────────┘
//!                              │
//!                    ┌─────────▼──────────┐
//!                    │  Distributed       │
//!                    │  Session Storage   │
//!                    │  (Redis/Database)  │
//!                    └────────────────────┘
//!
//! Each service can:
//! 每个服务可以：
//!   1. Create sessions for users
//!      为用户创建会话
//!   2. Access sessions created by other services
//!      访问其他服务创建的会话
//!   3. Share user authentication state
//!      共享用户认证状态
//! ```
//!
//! ## Key Use Cases | 关键使用场景
//!
//! ### 1. Single Sign-On (SSO) Across Services | 跨服务单点登录
//!
//! ```text
//! Scenario: User logs in to Service A and accesses Service B
//! 场景：用户登录服务 A 并访问服务 B
//!
//! 1. User → Service A: Login
//!    用户 → 服务 A：登录
//!    ├─ Service A creates session: session_id = "abc123"
//!    │  服务 A 创建会话：session_id = "abc123"
//!    └─ Saves to distributed storage
//!       保存到分布式存储
//!
//! 2. User → Service B: Request with session_id = "abc123"
//!    用户 → 服务 B：请求带 session_id = "abc123"
//!    ├─ Service B retrieves session from storage
//!    │  服务 B 从存储中获取会话
//!    ├─ Validates user is authenticated
//!    │  验证用户已认证
//!    └─ Processes request ✅
//!       处理请求 ✅
//!
//! No need to log in again! 无需再次登录！
//! ```
//!
//! ### 2. Session Sharing for User Context | 会话共享用户上下文
//!
//! ```text
//! Service A stores: { "user_role": "admin", "department": "IT" }
//! 服务 A 存储：{ "user_role": "admin", "department": "IT" }
//!
//! Service B reads: Same session attributes available
//! 服务 B 读取：相同的会话属性可用
//!
//! Service C updates: { "last_order": "order_123" }
//! 服务 C 更新：{ "last_order": "order_123" }
//!
//! All services share the same session state!
//! 所有服务共享相同的会话状态！
//! ```
//!
//! ### 3. Multi-Device Session Management | 多设备会话管理
//!
//! ```text
//! User: user_123
//!   ├─ Session 1: Web (Service A)
//!   │  会话 1：网页（服务 A）
//!   ├─ Session 2: Mobile (Service B)
//!   │  会话 2：移动端（服务 B）
//!   └─ Session 3: Desktop (Service C)
//!      会话 3：桌面端（服务 C）
//!
//! All sessions can be:
//! 所有会话可以：
//!   - Listed: get_sessions_by_login_id()
//!   - Managed individually
//!   - Terminated all at once: delete_all_sessions()
//! ```
//!
//! ## Integration with Sa-Token | 与 Sa-Token 的集成
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │               Sa-Token Core Flow                        │
//! │               Sa-Token 核心流程                          │
//! └─────────────────────────────────────────────────────────┘
//!
//! SaTokenManager::login()
//!   ├─ 1. Generate token
//!   │     生成 token
//!   ├─ 2. Create TokenInfo
//!   │     创建 TokenInfo
//!   └─ 3. Create DistributedSession (if enabled)
//!          创建 DistributedSession（如果启用）
//!          ├─ session_id: UUID
//!          ├─ login_id: user's login ID
//!          ├─ token: access token
//!          ├─ service_id: current service
//!          └─ attributes: custom data
//!
//! StpUtil::get_session()
//!   └─ Retrieves distributed session
//!      获取分布式会话
//!
//! StpUtil::logout()
//!   └─ Deletes distributed session(s)
//!      删除分布式会话
//! ```

//!
//! ## Workflow Diagrams | 工作流程图
//!
//! ### Complete Session Lifecycle | 完整会话生命周期
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                    Session Lifecycle                             │
//! │                    会话生命周期                                   │
//! └──────────────────────────────────────────────────────────────────┘
//!
//! User                Service A           Storage           Service B
//! 用户                服务 A              存储              服务 B
//!  │                     │                   │                   │
//!  │  1. Login           │                   │                   │
//!  │  登录               │                   │                   │
//!  ├────────────────────▶│                   │                   │
//!  │                     │  2. create_session()                  │
//!  │                     │  创建会话          │                   │
//!  │                     │  ├─ session_id: uuid                  │
//!  │                     │  ├─ login_id: user_123                │
//!  │                     │  ├─ token: access_token               │
//!  │                     │  └─ service_id: service-a             │
//!  │                     │                   │                   │
//!  │                     │  3. save_session()│                   │
//!  │                     │  保存会话          │                   │
//!  │                     ├──────────────────▶│                   │
//!  │                     │                   │  Store with TTL   │
//!  │                     │                   │  存储并设置 TTL    │
//!  │                     │                   │                   │
//!  │  4. session_id      │                   │                   │
//!  │  返回会话 ID        │                   │                   │
//!  │◀────────────────────│                   │                   │
//!  │                     │                   │                   │
//!  │  5. Request to Service B with session_id                    │
//!  │  带 session_id 请求服务 B                                    │
//!  ├────────────────────────────────────────────────────────────▶│
//!  │                     │                   │                   │
//!  │                     │                   │  6. get_session() │
//!  │                     │                   │  获取会话          │
//!  │                     │                   │◀──────────────────│
//!  │                     │                   │                   │
//!  │                     │                   │  7. Return session│
//!  │                     │                   │  返回会话数据      │
//!  │                     │                   ├──────────────────▶│
//!  │                     │                   │                   │
//!  │                     │                   │  8. refresh_session()
//!  │                     │                   │  刷新会话          │
//!  │                     │                   │  (update last_access)
//!  │                     │                   │◀──────────────────│
//!  │                     │                   │                   │
//!  │  9. Response        │                   │                   │
//!  │  响应               │                   │                   │
//!  │◀────────────────────────────────────────────────────────────│
//!  │                     │                   │                   │
//!  │  10. Logout         │                   │                   │
//!  │  登出               │                   │                   │
//!  ├────────────────────▶│                   │                   │
//!  │                     │  11. delete_session()                 │
//!  │                     │  删除会话          │                   │
//!  │                     ├──────────────────▶│                   │
//!  │                     │                   │  Remove from storage
//!  │                     │                   │  从存储中移除      │
//!  │                     │                   │                   │
//!  │  12. Logout Success │                   │                   │
//!  │  登出成功           │                   │                   │
//!  │◀────────────────────│                   │                   │
//!  │                     │                   │                   │
//! ```
//!
//! ### Service Authentication Flow | 服务认证流程
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                Service Inter-Communication                       │
//! │                服务间通信                                         │
//! └──────────────────────────────────────────────────────────────────┘
//!
//! Service B          Service A (Session Manager)          Storage
//! 服务 B             服务 A（会话管理器）                  存储
//!   │                        │                               │
//!   │  1. Register           │                               │
//!   │  注册服务              │                               │
//!   │  ├─ service_id         │                               │
//!   │  ├─ service_name       │                               │
//!   │  ├─ secret_key         │                               │
//!   │  └─ permissions        │                               │
//!   ├───────────────────────▶│                               │
//!   │                        │  Store credentials            │
//!   │                        │  存储凭证                      │
//!   │                        │  (in memory)                  │
//!   │                        │                               │
//!   │  2. Registered ✅      │                               │
//!   │◀───────────────────────│                               │
//!   │                        │                               │
//!   │  3. Access session     │                               │
//!   │  访问会话              │                               │
//!   │  ├─ service_id         │                               │
//!   │  ├─ secret_key         │                               │
//!   │  └─ session_id         │                               │
//!   ├───────────────────────▶│                               │
//!   │                        │  4. verify_service()          │
//!   │                        │  验证服务                      │
//!   │                        │  ├─ Lookup service            │
//!   │                        │  └─ Compare secret_key        │
//!   │                        │                               │
//!   │                        │  5. get_session()             │
//!   │                        │  获取会话                      │
//!   │                        ├──────────────────────────────▶│
//!   │                        │                               │
//!   │                        │  6. Return session            │
//!   │                        │  返回会话                      │
//!   │                        │◀──────────────────────────────│
//!   │                        │                               │
//!   │  7. Session data ✅    │                               │
//!   │◀───────────────────────│                               │
//!   │                        │                               │
//! ```
//!
//! ## Storage Backends | 存储后端
//!
//! The module is storage-agnostic. You can implement custom backends:
//! 本模块与存储无关。您可以实现自定义后端：
//!
//! ### Redis Implementation (Recommended) | Redis 实现（推荐）
//!
//! ```rust,ignore
//! use redis::AsyncCommands;
//!
//! pub struct RedisDistributedStorage {
//!     client: redis::Client,
//! }
//!
//! #[async_trait]
//! impl DistributedSessionStorage for RedisDistributedStorage {
//!     async fn save_session(&self, session: DistributedSession, ttl: Option<Duration>)
//!         -> Result<(), SaTokenError>
//!     {
//!         let mut conn = self.client.get_async_connection().await?;
//!         let key = format!("distributed:session:{}", session.session_id);
//!         let value = serde_json::to_string(&session)?;
//!         
//!         if let Some(ttl) = ttl {
//!             conn.set_ex(&key, value, ttl.as_secs() as usize).await?;
//!         } else {
//!             conn.set(&key, value).await?;
//!         }
//!         
//!         // Index by login_id
//!         let index_key = format!("distributed:login:{}", session.login_id);
//!         conn.sadd(index_key, &session.session_id).await?;
//!         
//!         Ok(())
//!     }
//!     
//!     // ... other methods
//! }
//! ```
//!
//! ### Database Implementation | 数据库实现
//!
//! ```rust,ignore
//! use sqlx::PgPool;
//!
//! pub struct PostgresDistributedStorage {
//!     pool: PgPool,
//! }
//!
//! #[async_trait]
//! impl DistributedSessionStorage for PostgresDistributedStorage {
//!     async fn save_session(&self, session: DistributedSession, ttl: Option<Duration>)
//!         -> Result<(), SaTokenError>
//!     {
//!         let expires_at = ttl.map(|t| Utc::now() + chrono::Duration::from_std(t).unwrap());
//!         
//!         sqlx::query!(
//!             "INSERT INTO distributed_sessions
//!              (session_id, login_id, token, service_id, attributes, expires_at)
//!              VALUES ($1, $2, $3, $4, $5, $6)
//!              ON CONFLICT (session_id) DO UPDATE
//!              SET attributes = $5, last_access = NOW()",
//!             session.session_id,
//!             session.login_id,
//!             session.token,
//!             session.service_id,
//!             serde_json::to_value(&session.attributes)?,
//!             expires_at,
//!         )
//!         .execute(&self.pool)
//!         .await?;
//!         
//!         Ok(())
//!     }
//!     
//!     // ... other methods
//! }
//! ```
//!
//! ## Best Practices | 最佳实践
//!
//! ### 1. Service Registration | 服务注册
//!
//! ```rust,ignore
//! // Initialize each service with unique credentials
//! // 为每个服务初始化唯一凭证
//! let credential = ServiceCredential {
//!     service_id: "user-service".to_string(),
//!     service_name: "User Management Service".to_string(),
//!     secret_key: generate_secure_secret(), // Use crypto-secure generation
//!     created_at: Utc::now(),
//!     permissions: vec!["user.read".to_string(), "user.write".to_string()],
//! };
//! manager.register_service(credential).await;
//! ```
//!
//! ### 2. Session Creation with Context | 带上下文的会话创建
//!
//! ```rust,ignore
//! // Create session with user context
//! // 创建带用户上下文的会话
//! let session = manager.create_session(login_id, token).await?;
//!
//! // Add relevant attributes immediately
//! // 立即添加相关属性
//! manager.set_attribute(&session.session_id, "user_role".to_string(), "admin".to_string()).await?;
//! manager.set_attribute(&session.session_id, "department".to_string(), "IT".to_string()).await?;
//! manager.set_attribute(&session.session_id, "login_device".to_string(), "web".to_string()).await?;
//! ```
//!
//! ### 3. Cross-Service Access Pattern | 跨服务访问模式
//!
//! ```rust,ignore
//! // Service B accesses session created by Service A
//! // 服务 B 访问服务 A 创建的会话
//!
//! // 1. Verify service identity
//! // 验证服务身份
//! let service_cred = manager.verify_service("service-b", request.secret).await?;
//!
//! // 2. Check permissions
//! // 检查权限
//! if !service_cred.permissions.contains(&"session.read".to_string()) {
//!     return Err(SaTokenError::PermissionDenied);
//! }
//!
//! // 3. Access session
//! // 访问会话
//! let session = manager.get_session(&request.session_id).await?;
//!
//! // 4. Refresh to keep session alive
//! // 刷新以保持会话活跃
//! manager.refresh_session(&session.session_id).await?;
//! ```
//!
//! ### 4. Multi-Device Logout | 多设备登出
//!
//! ```rust,ignore
//! // Logout from all devices
//! // 从所有设备登出
//! manager.delete_all_sessions(&login_id).await?;
//!
//! // Or logout specific session
//! // 或登出特定会话
//! manager.delete_session(&session_id).await?;
//! ```
//!
//! ### 5. Session Monitoring | 会话监控
//!
//! ```rust,ignore
//! // Monitor user's active sessions
//! // 监控用户的活跃会话
//! let sessions = manager.get_sessions_by_login_id(&login_id).await?;
//!
//! for session in sessions {
//!     println!("Session: {} from service: {}, last active: {}",
//!         session.session_id,
//!         session.service_id,
//!         session.last_access
//!     );
//!     
//!     // Check for suspicious activity
//!     // 检查可疑活动
//!     if is_suspicious(&session) {
//!         manager.delete_session(&session.session_id).await?;
//!     }
//! }
//! ```
//!
//! ## Security Considerations | 安全考虑
//!
//! ```text
//! 1. ✅ Service Authentication | 服务认证
//!    - Each service has unique secret_key
//!    - Verify credentials before granting access
//!    - Rotate keys periodically
//!
//! 2. ✅ Permission-Based Access | 基于权限的访问
//!    - Services have explicit permissions
//!    - Check permissions before operations
//!    - Implement least-privilege principle
//!
//! 3. ✅ Session Timeout | 会话超时
//!    - Configure appropriate TTL
//!    - Auto-expire inactive sessions
//!    - Refresh on active use
//!
//! 4. ✅ Data Encryption | 数据加密
//!    - Encrypt sensitive session attributes
//!    - Use TLS for inter-service communication
//!    - Encrypt data at rest in storage
//!
//! 5. ✅ Audit Logging | 审计日志
//!    - Log session creation/deletion
//!    - Track cross-service access
//!    - Monitor for anomalies
//! ```

use crate::config::SaTokenConfig;
use crate::dao::SaTokenDao;
use crate::error::SaTokenError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sa_token_adapter::storage::SaStorage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Distributed session data structure
/// 分布式 Session 数据结构
///
/// Represents a session that can be shared across multiple services
/// 表示可以在多个服务之间共享的 Session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedSession {
    /// Unique session identifier | 唯一 Session 标识符
    pub session_id: String,

    /// User login ID | 用户登录 ID
    pub login_id: String,

    /// Authentication token | 认证 Token
    pub token: String,

    /// ID of the service that created this session | 创建此 Session 的服务 ID
    pub service_id: String,

    /// Session creation time | Session 创建时间
    pub create_time: DateTime<Utc>,

    /// Last access time | 最后访问时间
    pub last_access: DateTime<Utc>,

    /// Session attributes (key-value pairs) | Session 属性（键值对）
    pub attributes: HashMap<String, String>,
}

/// Service credential for inter-service authentication
/// 服务间认证的服务凭证
///
/// Contains service identification and permission information
/// 包含服务标识和权限信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCredential {
    /// Unique service identifier | 唯一服务标识符
    pub service_id: String,

    /// Human-readable service name | 可读的服务名称
    pub service_name: String,

    /// Service authentication secret key | 服务认证密钥
    pub secret_key: String,

    /// Service registration time | 服务注册时间
    pub created_at: DateTime<Utc>,

    /// List of permissions this service has | 该服务拥有的权限列表
    pub permissions: Vec<String>,
}

/// Distributed session storage trait
/// 分布式 Session 存储 trait
///
/// Implement this trait to provide custom storage backends
/// 实现此 trait 以提供自定义存储后端
#[async_trait]
pub trait DistributedSessionStorage: Send + Sync {
    /// Save a session to storage with optional TTL
    /// 保存 Session 到存储，可选 TTL
    ///
    /// # Arguments | 参数
    /// * `session` - Session to save | 要保存的 Session
    /// * `ttl` - Time-to-live duration | 生存时间
    async fn save_session(
        &self,
        session: DistributedSession,
        ttl: Option<Duration>,
    ) -> Result<(), SaTokenError>;

    /// Get a session from storage
    /// 从存储获取 Session
    ///
    /// # Arguments | 参数
    /// * `session_id` - Session identifier | Session 标识符
    async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<DistributedSession>, SaTokenError>;

    /// Delete a session from storage
    /// 从存储删除 Session
    ///
    /// # Arguments | 参数
    /// * `session_id` - Session identifier | Session 标识符
    async fn delete_session(&self, session_id: &str) -> Result<(), SaTokenError>;

    /// Get all sessions for a specific user
    /// 获取特定用户的所有 Sessions
    ///
    /// # Arguments | 参数
    /// * `login_id` - User login ID | 用户登录 ID
    async fn get_sessions_by_login_id(
        &self,
        login_id: &str,
    ) -> Result<Vec<DistributedSession>, SaTokenError>;

    /// 保存服务凭证 | Save a service credential
    /// 用于把 register_service 的凭证持久化到存储
    async fn save_credential(&self, credential: ServiceCredential) -> Result<(), SaTokenError>;

    /// 按 service_id 获取服务凭证 | Get a service credential by service_id
    /// 未找到返回 Ok(None)
    async fn get_credential(
        &self,
        service_id: &str,
    ) -> Result<Option<ServiceCredential>, SaTokenError>;
}

/// Distributed session manager
/// 分布式 Session 管理器
///
/// Manages distributed sessions and service authentication
/// 管理分布式 Sessions 和服务认证
pub struct DistributedSessionManager {
    /// Session 存储后端
    storage: Arc<dyn DistributedSessionStorage>,
    /// 当前服务 ID
    service_id: String,
    /// 默认 Session 超时时间
    session_timeout: Duration,
}

impl std::fmt::Debug for DistributedSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DistributedSessionManager { .. }")
    }
}

impl DistributedSessionManager {
    /// Create a new distributed session manager
    /// 创建新的分布式 Session 管理器
    ///
    /// # Arguments | 参数
    /// * `storage` - Session storage implementation | Session 存储实现
    /// * `service_id` - ID of this service | 此服务的 ID
    /// * `session_timeout` - Default session timeout | 默认 Session 超时时间
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// let storage = Arc::new(MyDistributedStorage::new());
    /// let manager = DistributedSessionManager::new(
    ///     storage,
    ///     "my-service".to_string(),
    ///     Duration::from_secs(3600),
    /// );
    /// ```
    pub fn new(
        storage: Arc<dyn DistributedSessionStorage>,
        service_id: String,
        session_timeout: Duration,
    ) -> Self {
        Self {
            storage,
            service_id,
            session_timeout,
        }
    }

    /// 注册服务凭证（持久化到底层存储）
    /// 返回 Result 以便调用方处理存储错误
    pub async fn register_service(
        &self,
        credential: ServiceCredential,
    ) -> Result<(), SaTokenError> {
        self.storage.save_credential(credential).await
    }

    /// Verify a service's credentials
    /// 验证服务的凭证
    ///
    /// # Arguments | 参数
    /// * `service_id` - Service identifier | 服务标识符
    /// * `secret` - Service secret key | 服务密钥
    ///
    /// # Returns | 返回值
    /// * `Ok(ServiceCredential)` - Service authenticated | 服务已认证
    /// * `Err(PermissionDenied)` - Invalid credentials | 凭证无效
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// match manager.verify_service("api-gateway", "secret123").await {
    ///     Ok(cred) => println!("Service {} verified", cred.service_name),
    ///     Err(e) => println!("Verification failed: {}", e),
    /// }
    /// ```
    /// 校验服务凭证
    /// service_id 存在且 secret_key 匹配时返回凭证，否则返回 PermissionDenied
    pub async fn verify_service(
        &self,
        service_id: &str,
        secret: &str,
    ) -> Result<ServiceCredential, SaTokenError> {
        if let Some(cred) = self.storage.get_credential(service_id).await?
            && crate::http_basic::ct_eq(cred.secret_key.as_bytes(), secret.as_bytes())
        {
            return Ok(cred);
        }
        Err(SaTokenError::PermissionDenied)
    }

    /// Create a new distributed session
    /// 创建新的分布式 Session
    ///
    /// # Arguments | 参数
    /// * `login_id` - User login ID | 用户登录 ID
    /// * `token` - Authentication token | 认证 Token
    ///
    /// # Returns | 返回值
    /// * `Ok(DistributedSession)` - Session created | Session 已创建
    /// * `Err(SaTokenError)` - Creation failed | 创建失败
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// let session = manager.create_session(
    ///     "user123".to_string(),
    ///     "token456".to_string(),
    /// ).await?;
    /// println!("Session created: {}", session.session_id);
    /// ```
    pub async fn create_session(
        &self,
        login_id: String,
        token: String,
    ) -> Result<DistributedSession, SaTokenError> {
        let session = DistributedSession {
            session_id: uuid::Uuid::new_v4().to_string(),
            login_id,
            token,
            service_id: self.service_id.clone(),
            create_time: Utc::now(),
            last_access: Utc::now(),
            attributes: HashMap::new(),
        };

        self.storage
            .save_session(session.clone(), Some(self.session_timeout))
            .await?;
        Ok(session)
    }

    /// Get a session by ID
    /// 通过 ID 获取 Session
    ///
    /// # Arguments | 参数
    /// * `session_id` - Session identifier | Session 标识符
    ///
    /// # Returns | 返回值
    /// * `Ok(DistributedSession)` - Session found | 找到 Session
    /// * `Err(SessionNotFound)` - Session not found | 未找到 Session
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// let session = manager.get_session("session-id-123").await?;
    /// println!("User: {}", session.login_id);
    /// ```
    pub async fn get_session(&self, session_id: &str) -> Result<DistributedSession, SaTokenError> {
        self.storage
            .get_session(session_id)
            .await?
            .ok_or(SaTokenError::SessionNotFound)
    }

    /// Update an existing session
    /// 更新现有 Session
    ///
    /// # Arguments | 参数
    /// * `session` - Updated session data | 更新后的 Session 数据
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// let mut session = manager.get_session("session-id").await?;
    /// session.attributes.insert("role".to_string(), "admin".to_string());
    /// manager.update_session(session).await?;
    /// ```
    pub async fn update_session(&self, session: DistributedSession) -> Result<(), SaTokenError> {
        self.storage
            .save_session(session, Some(self.session_timeout))
            .await
    }

    /// Delete a session
    /// 删除 Session
    ///
    /// # Arguments | 参数
    /// * `session_id` - Session identifier | Session 标识符
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// manager.delete_session("session-id-123").await?;
    /// ```
    pub async fn delete_session(&self, session_id: &str) -> Result<(), SaTokenError> {
        self.storage.delete_session(session_id).await
    }

    /// Refresh a session (update last access time)
    /// 刷新 Session（更新最后访问时间）
    ///
    /// # Arguments | 参数
    /// * `session_id` - Session identifier | Session 标识符
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// manager.refresh_session("session-id-123").await?;
    /// ```
    pub async fn refresh_session(&self, session_id: &str) -> Result<(), SaTokenError> {
        let mut session = self.get_session(session_id).await?;
        session.last_access = Utc::now();
        self.update_session(session).await
    }

    /// Set a session attribute
    /// 设置 Session 属性
    ///
    /// # Arguments | 参数
    /// * `session_id` - Session identifier | Session 标识符
    /// * `key` - Attribute key | 属性键
    /// * `value` - Attribute value | 属性值
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// manager.set_attribute("session-id", "theme".to_string(), "dark".to_string()).await?;
    /// ```
    pub async fn set_attribute(
        &self,
        session_id: &str,
        key: String,
        value: String,
    ) -> Result<(), SaTokenError> {
        let mut session = self.get_session(session_id).await?;
        session.attributes.insert(key, value);
        session.last_access = Utc::now();
        self.update_session(session).await
    }

    /// Get a session attribute
    /// 获取 Session 属性
    ///
    /// # Arguments | 参数
    /// * `session_id` - Session identifier | Session 标识符
    /// * `key` - Attribute key | 属性键
    ///
    /// # Returns | 返回值
    /// * `Some(value)` - Attribute found | 找到属性
    /// * `None` - Attribute not found | 未找到属性
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// if let Some(theme) = manager.get_attribute("session-id", "theme").await? {
    ///     println!("Theme: {}", theme);
    /// }
    /// ```
    pub async fn get_attribute(
        &self,
        session_id: &str,
        key: &str,
    ) -> Result<Option<String>, SaTokenError> {
        let session = self.get_session(session_id).await?;
        Ok(session.attributes.get(key).cloned())
    }

    /// Remove a session attribute
    /// 移除 Session 属性
    ///
    /// # Arguments | 参数
    /// * `session_id` - Session identifier | Session 标识符
    /// * `key` - Attribute key | 属性键
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// manager.remove_attribute("session-id", "temp_data").await?;
    /// ```
    pub async fn remove_attribute(&self, session_id: &str, key: &str) -> Result<(), SaTokenError> {
        let mut session = self.get_session(session_id).await?;
        session.attributes.remove(key);
        session.last_access = Utc::now();
        self.update_session(session).await
    }

    /// Get all sessions for a specific user
    /// 获取特定用户的所有 Sessions
    ///
    /// # Arguments | 参数
    /// * `login_id` - User login ID | 用户登录 ID
    ///
    /// # Returns | 返回值
    /// Vector of sessions | Sessions 向量
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// let sessions = manager.get_sessions_by_login_id("user123").await?;
    /// println!("User has {} active sessions", sessions.len());
    /// ```
    pub async fn get_sessions_by_login_id(
        &self,
        login_id: &str,
    ) -> Result<Vec<DistributedSession>, SaTokenError> {
        self.storage.get_sessions_by_login_id(login_id).await
    }

    /// Delete all sessions for a specific user
    /// 删除特定用户的所有 Sessions
    ///
    /// # Arguments | 参数
    /// * `login_id` - User login ID | 用户登录 ID
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// manager.delete_all_sessions("user123").await?;
    /// ```
    pub async fn delete_all_sessions(&self, login_id: &str) -> Result<(), SaTokenError> {
        let sessions = self.get_sessions_by_login_id(login_id).await?;
        for session in sessions {
            self.delete_session(&session.session_id).await?;
        }
        Ok(())
    }

    /// Delete distributed sessions that carry this access token (one device).
    /// 只删携带该 access token 的分布式会话（单设备），避免误杀其它终端。
    pub async fn delete_sessions_by_token(
        &self,
        login_id: &str,
        token: &str,
    ) -> Result<(), SaTokenError> {
        let sessions = self.storage.get_sessions_by_login_id(login_id).await?;
        for session in sessions {
            if crate::http_basic::ct_eq(session.token.as_bytes(), token.as_bytes()) {
                self.storage.delete_session(&session.session_id).await?;
            }
        }
        Ok(())
    }
}

/// In-memory distributed session storage (process-local only; not cross-instance).
/// 内存分布式 Session 存储（仅进程内，不能跨实例）。
///
/// For testing and local demos — do not use as shared multi-node storage.
/// 用于测试与本地演示 —— 不可作为多节点共享存储。
pub struct InMemoryDistributedStorage {
    /// Sessions 存储: session_id -> DistributedSession
    sessions: Arc<RwLock<HashMap<String, DistributedSession>>>,
    /// 登录索引: login_id -> Vec<session_id>
    login_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// 服务凭证: service_id -> ServiceCredential
    credentials: Arc<RwLock<HashMap<String, ServiceCredential>>>,
}

impl std::fmt::Debug for InMemoryDistributedStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InMemoryDistributedStorage { .. }")
    }
}

impl InMemoryDistributedStorage {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            login_index: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryDistributedStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DistributedSessionStorage for InMemoryDistributedStorage {
    /// Save session to memory storage | 保存会话到内存存储
    ///
    /// # Implementation Details | 实现细节
    ///
    /// 1. Stores session in main HashMap by session_id
    ///    在主 HashMap 中按 session_id 存储会话
    /// 2. Updates login_index for quick user lookup
    ///    更新 login_index 以快速查找用户
    ///
    /// # Note | 注意
    ///
    /// TTL is ignored in memory storage (for simplicity).
    /// In production, use Redis or similar with built-in TTL support.
    /// 内存存储中忽略 TTL（为简化实现）。
    /// 在生产环境中，使用 Redis 或类似的内置 TTL 支持的存储。
    async fn save_session(
        &self,
        session: DistributedSession,
        _ttl: Option<Duration>,
    ) -> Result<(), SaTokenError> {
        let session_id = session.session_id.clone();
        let login_id = session.login_id.clone();

        // 1. Store session in main map
        // 在主映射中存储会话
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);

        // 2. Update login index for this user
        // 更新此用户的登录索引
        let mut index = self.login_index.write().await;
        let session_list = index.entry(login_id).or_insert_with(Vec::new);

        // Add only if not already present (prevent duplicates)
        // 仅在不存在时添加（防止重复）
        if !session_list.contains(&session_id) {
            session_list.push(session_id);
        }

        Ok(())
    }

    /// Get session from memory storage | 从内存存储获取会话
    ///
    /// # Returns | 返回
    ///
    /// * `Ok(Some(session))` - Session found | 找到会话
    /// * `Ok(None)` - Session not found | 未找到会话
    async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<DistributedSession>, SaTokenError> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }

    /// Delete session from memory storage | 从内存存储删除会话
    ///
    /// # Implementation Details | 实现细节
    ///
    /// 1. Removes session from main HashMap
    ///    从主 HashMap 中移除会话
    /// 2. Removes session_id from login_index
    ///    从 login_index 中移除 session_id
    /// 3. Cleans up empty index entries
    ///    清理空的索引条目
    async fn delete_session(&self, session_id: &str) -> Result<(), SaTokenError> {
        // 1. Remove from main storage and get session data
        // 从主存储中移除并获取会话数据
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(session_id) {
            // 2. Update login index
            // 更新登录索引
            let mut index = self.login_index.write().await;
            if let Some(session_ids) = index.get_mut(&session.login_id) {
                // Remove this session_id from the list
                // 从列表中移除此 session_id
                session_ids.retain(|id| id != session_id);

                // 3. Clean up: remove login_id entry if no sessions left
                // 清理：如果没有剩余会话，移除 login_id 条目
                if session_ids.is_empty() {
                    index.remove(&session.login_id);
                }
            }
        }
        Ok(())
    }

    /// Get all sessions for a user | 获取用户的所有会话
    ///
    /// # Implementation Details | 实现细节
    ///
    /// 1. Looks up session_ids in login_index
    ///    在 login_index 中查找 session_ids
    /// 2. Retrieves full session data for each session_id
    ///    为每个 session_id 检索完整的会话数据
    /// 3. Filters out any missing sessions (cleanup)
    ///    过滤掉任何缺失的会话（清理）
    ///
    /// # Returns | 返回
    ///
    /// Vector of all active sessions for the user
    /// 用户所有活跃会话的向量
    async fn get_sessions_by_login_id(
        &self,
        login_id: &str,
    ) -> Result<Vec<DistributedSession>, SaTokenError> {
        // 1. Get session IDs from index
        // 从索引中获取会话 IDs
        let index = self.login_index.read().await;
        let session_ids = index.get(login_id).cloned().unwrap_or_default();

        // 2. Retrieve full session data
        // 检索完整的会话数据
        let sessions = self.sessions.read().await;
        let mut result = Vec::new();

        for session_id in session_ids {
            if let Some(session) = sessions.get(&session_id) {
                result.push(session.clone());
            }
            // Note: If session not found, it was deleted but index not updated
            // This is a minor inconsistency acceptable in memory storage
            // 注意：如果未找到会话，说明会话已删除但索引未更新
            // 这是内存存储中可接受的小不一致
        }

        Ok(result)
    }

    /// 保存服务凭证到内存
    async fn save_credential(&self, credential: ServiceCredential) -> Result<(), SaTokenError> {
        let mut creds = self.credentials.write().await;
        creds.insert(credential.service_id.clone(), credential);
        Ok(())
    }

    /// 从内存获取服务凭证
    async fn get_credential(
        &self,
        service_id: &str,
    ) -> Result<Option<ServiceCredential>, SaTokenError> {
        let creds = self.credentials.read().await;
        Ok(creds.get(service_id).cloned())
    }
}

/// Persist distributed sessions through SaTokenDao (same serializer and keys as login).
/// 经 SaTokenDao 持久化分布式会话（与登录共用序列化器和键）。
pub struct SaStorageDistributedStorage {
    dao: Arc<SaTokenDao>,
}

impl std::fmt::Debug for SaStorageDistributedStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SaStorageDistributedStorage { .. }")
    }
}

impl SaStorageDistributedStorage {
    /// `from_dao` — from dao | `from_dao`
    pub fn from_dao(dao: Arc<SaTokenDao>) -> Self {
        Self { dao }
    }

    /// Compatibility wrapper: builds a Dao from raw storage + prefix.
    /// 兼容包装：从原始存储与前缀构造 Dao。
    pub fn from_config(storage: Arc<dyn SaStorage>, config: &SaTokenConfig) -> Self {
        Self::from_dao(Arc::new(SaTokenDao::new(storage, Arc::new(config.clone()))))
    }

    /// Create a new instance | 创建新实例
    pub fn new(storage: Arc<dyn SaStorage>, key_prefix: impl Into<String>) -> Self {
        let config = SaTokenConfig {
            storage_key_prefix: key_prefix.into(),
            ..SaTokenConfig::default()
        };
        Self::from_config(storage, &config)
    }
}

#[async_trait]
impl DistributedSessionStorage for SaStorageDistributedStorage {
    async fn save_session(
        &self,
        session: DistributedSession,
        ttl: Option<Duration>,
    ) -> Result<(), SaTokenError> {
        let session_key = self.dao.keys().distributed_session(&session.session_id);
        let index_key = self.dao.keys().distributed_session_index(&session.login_id);
        self.dao.set_object(&session_key, &session, ttl).await?;
        self.dao
            .list_push_unique(&index_key, &session.session_id, None)
            .await?;
        Ok(())
    }

    async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<DistributedSession>, SaTokenError> {
        self.dao
            .get_object(&self.dao.keys().distributed_session(session_id))
            .await
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), SaTokenError> {
        if let Some(session) = self.get_session(session_id).await? {
            self.dao
                .delete(&self.dao.keys().distributed_session(session_id))
                .await?;
            let index_key = self.dao.keys().distributed_session_index(&session.login_id);
            self.dao.list_remove(&index_key, session_id).await?;
            if self.dao.list_len(&index_key).await? == 0 {
                self.dao.delete(&index_key).await?;
            }
        } else {
            self.dao
                .delete(&self.dao.keys().distributed_session(session_id))
                .await?;
        }
        Ok(())
    }

    async fn get_sessions_by_login_id(
        &self,
        login_id: &str,
    ) -> Result<Vec<DistributedSession>, SaTokenError> {
        let index_key = self.dao.keys().distributed_session_index(login_id);
        let ids = self.dao.list_range(&index_key, 0, None).await?;
        let mut out = Vec::new();
        for id in ids {
            match self.get_session(&id).await? {
                Some(s) => out.push(s),
                None => {
                    self.dao.list_remove(&index_key, &id).await?;
                }
            }
        }
        Ok(out)
    }

    async fn save_credential(&self, credential: ServiceCredential) -> Result<(), SaTokenError> {
        let key = self.dao.keys().distributed_service(&credential.service_id);
        self.dao.set_object(&key, &credential, None).await
    }

    async fn get_credential(
        &self,
        service_id: &str,
    ) -> Result<Option<ServiceCredential>, SaTokenError> {
        self.dao
            .get_object(&self.dao.keys().distributed_service(service_id))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_distributed_session_manager() {
        let storage = Arc::new(InMemoryDistributedStorage::new());
        let manager = DistributedSessionManager::new(
            storage,
            "service1".to_string(),
            Duration::from_secs(3600),
        );

        let session = manager
            .create_session("user1".to_string(), "token1".to_string())
            .await
            .unwrap();

        let retrieved = manager.get_session(&session.session_id).await.unwrap();
        assert_eq!(retrieved.login_id, "user1");
    }

    #[tokio::test]
    async fn test_session_attributes() {
        let storage = Arc::new(InMemoryDistributedStorage::new());
        let manager = DistributedSessionManager::new(
            storage,
            "service1".to_string(),
            Duration::from_secs(3600),
        );

        let session = manager
            .create_session("user2".to_string(), "token2".to_string())
            .await
            .unwrap();

        manager
            .set_attribute(
                &session.session_id,
                "key1".to_string(),
                "value1".to_string(),
            )
            .await
            .unwrap();

        let value = manager
            .get_attribute(&session.session_id, "key1")
            .await
            .unwrap();
        assert_eq!(value, Some("value1".to_string()));
    }

    #[tokio::test]
    async fn test_service_verification() {
        let storage = Arc::new(InMemoryDistributedStorage::new());
        let manager = DistributedSessionManager::new(
            storage,
            "service1".to_string(),
            Duration::from_secs(3600),
        );

        let credential = ServiceCredential {
            service_id: "service2".to_string(),
            service_name: "Service 2".to_string(),
            secret_key: "secret123".to_string(),
            created_at: Utc::now(),
            permissions: vec!["read".to_string(), "write".to_string()],
        };

        manager.register_service(credential.clone()).await.unwrap();

        let verified = manager
            .verify_service("service2", "secret123")
            .await
            .unwrap();
        assert_eq!(verified.service_id, "service2");

        let result = manager.verify_service("service2", "wrong_secret").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_all_sessions() {
        let storage = Arc::new(InMemoryDistributedStorage::new());
        let manager = DistributedSessionManager::new(
            storage,
            "service1".to_string(),
            Duration::from_secs(3600),
        );

        manager
            .create_session("user3".to_string(), "token1".to_string())
            .await
            .unwrap();
        manager
            .create_session("user3".to_string(), "token2".to_string())
            .await
            .unwrap();

        let sessions = manager.get_sessions_by_login_id("user3").await.unwrap();
        assert_eq!(sessions.len(), 2);

        manager.delete_all_sessions("user3").await.unwrap();

        let sessions = manager.get_sessions_by_login_id("user3").await.unwrap();
        assert_eq!(sessions.len(), 0);
    }
}
