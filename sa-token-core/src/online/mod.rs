// Author: 金书记 | Author: Jin Shuji
//! Online users and realtime push.
//! 在线用户与实时推送。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use crate::keys::LOGIN_TYPE_DEFAULT;

mod push;
mod store;

pub use push::dispatch_to_pushers;
pub use store::{DistributedOnlineStore, LocalOnlineStore, OnlineStore, StoredOnlineUser};

/// One live connection belonging to a login id.
/// 某个登录账号下的一条在线连接。
#[derive(Debug, Clone)]
pub struct OnlineUser {
    /// Account system; empty/`login` means default.
    /// 账号体系；空或 `login` 表示默认。
    pub login_type: String,
    /// Login id | 登录 ID
    pub login_id: String,
    /// Token value | Token 值
    pub token: String,
    /// Device / terminal label | 设备/终端标识
    pub device: String,
    /// First connect time | 首次连接时间
    pub connect_time: DateTime<Utc>,
    /// Last activity time | 最近活跃时间
    pub last_activity: DateTime<Utc>,
    /// Extra key-value metadata | 扩展元数据
    pub metadata: HashMap<String, String>,
}

impl OnlineUser {
    /// Build a presence record for the default account system.
    /// 为默认账号体系构造一条 presence 记录。
    pub fn new(
        login_id: impl Into<String>,
        token: impl Into<String>,
        device: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            login_type: LOGIN_TYPE_DEFAULT.to_string(),
            login_id: login_id.into(),
            token: token.into(),
            device: device.into(),
            connect_time: now,
            last_activity: now,
            metadata: HashMap::new(),
        }
    }
}

/// Push payload | 推送载荷
#[derive(Debug, Clone)]
pub struct PushMessage {
    /// Message id | 消息 ID
    pub message_id: String,
    /// Message body | 消息正文
    pub content: String,
    /// Message kind | 消息类型
    pub message_type: MessageType,
    /// Event timestamp | 事件时间戳
    pub timestamp: DateTime<Utc>,
    /// Extra key-value metadata | 扩展元数据
    pub metadata: HashMap<String, String>,
}

/// Message kind | 消息种类
#[derive(Debug, Clone, PartialEq)]
pub enum MessageType {
    /// Plain text | 纯文本
    Text,
    /// Binary payload | 二进制载荷
    Binary,
    /// Kick-out signal | 踢下线信号
    KickOut,
    /// Notification | 通知
    Notification,
    /// Custom message type | 自定义消息类型
    Custom(String),
}

/// Deliver a message to one user.
/// 向单个用户投递消息。
#[async_trait]
pub trait MessagePusher: Send + Sync {
    /// Push a message to the user | 向用户推送消息
    async fn push(&self, login_id: &str, message: PushMessage) -> Result<(), SaTokenError>;
}

/// Online user manager | 在线用户管理器
pub struct OnlineManager {
    store: Arc<dyn OnlineStore>,
    pushers: Arc<RwLock<Vec<Arc<dyn MessagePusher>>>>,
}

impl std::fmt::Debug for OnlineManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnlineManager { .. }")
    }
}

impl OnlineManager {
    /// Process-local (backward compatible).
    /// 进程内实现（保持旧 `new()` 语义）。
    pub fn new() -> Self {
        Self::local()
    }

    /// Process-local store | 进程内存储
    pub fn local() -> Self {
        Self {
            store: Arc::new(LocalOnlineStore::new()),
            pushers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Shared store; `entry_ttl` of 1 day bounds leaked WS rows.
    /// 共享存储；默认 1 天 TTL 限制异常断开造成的泄漏。
    pub fn distributed(dao: Arc<SaTokenDao>) -> Self {
        Self {
            store: Arc::new(DistributedOnlineStore::new(
                dao,
                Some(Duration::from_secs(86400)),
            )),
            pushers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Build with a custom [`OnlineStore`] | 使用自定义在线存储构建
    pub fn with_store(store: Arc<dyn OnlineStore>) -> Self {
        Self {
            store,
            pushers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register a realtime pusher | 注册实时推送器
    pub async fn register_pusher(&self, pusher: Arc<dyn MessagePusher>) {
        self.pushers.write().await.push(pusher);
    }

    /// Mark a user connection online | 标记用户连接在线
    pub async fn mark_online(&self, user: OnlineUser) -> SaTokenResult<()> {
        self.store.mark_online(user).await
    }

    /// Default account-system wrapper (old two-arg API).
    /// 默认账号体系包装（旧两参数 API）。
    pub async fn mark_offline(&self, login_id: &str, token: &str) -> SaTokenResult<()> {
        self.store
            .mark_offline(LOGIN_TYPE_DEFAULT, login_id, token)
            .await
    }

    /// Mark offline for a login type | 按登录类型标记离线
    pub async fn mark_offline_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
    ) -> SaTokenResult<()> {
        self.store.mark_offline(login_type, login_id, token).await
    }

    /// Mark all connections offline | 标记该账号全部离线
    pub async fn mark_offline_all(&self, login_id: &str) -> SaTokenResult<()> {
        self.store
            .mark_offline_all(LOGIN_TYPE_DEFAULT, login_id)
            .await
    }

    /// Mark all offline for a login type | 按登录类型全部离线
    pub async fn mark_offline_all_with_type(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<()> {
        self.store.mark_offline_all(login_type, login_id).await
    }

    /// Whether the login id is online | 登录 ID 是否在线
    pub async fn is_online(&self, login_id: &str) -> SaTokenResult<bool> {
        self.store.is_online(LOGIN_TYPE_DEFAULT, login_id).await
    }

    /// `get_online_count` — get online count | `get_online_count`
    pub async fn get_online_count(&self) -> SaTokenResult<usize> {
        self.store.get_online_count().await
    }

    /// List online users for a login id | 列出某登录 ID 的在线用户
    pub async fn get_online_users(&self) -> SaTokenResult<Vec<String>> {
        self.store.get_online_users().await
    }

    /// `get_user_sessions` — get user sessions | `get_user_sessions`
    pub async fn get_user_sessions(&self, login_id: &str) -> SaTokenResult<Vec<OnlineUser>> {
        self.store
            .get_user_sessions(LOGIN_TYPE_DEFAULT, login_id)
            .await
    }

    /// Refresh last-activity timestamp | 刷新最近活跃时间
    pub async fn update_activity(&self, login_id: &str, token: &str) -> SaTokenResult<()> {
        self.store
            .update_activity(LOGIN_TYPE_DEFAULT, login_id, token)
            .await
    }

    /// `update_activity_with_type` — update activity with type | `update_activity_with_type`
    pub async fn update_activity_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
    ) -> SaTokenResult<()> {
        self.store
            .update_activity(login_type, login_id, token)
            .await
    }

    async fn cloned_pushers(&self) -> Vec<Arc<dyn MessagePusher>> {
        self.pushers.read().await.clone()
    }

    /// `push_to_user` — push to user | `push_to_user`
    pub async fn push_to_user(&self, login_id: &str, content: String) -> SaTokenResult<()> {
        let message = PushMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            content,
            message_type: MessageType::Text,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        };
        let pushers = self.cloned_pushers().await;
        dispatch_to_pushers(&pushers, login_id, message).await
    }

    /// `push_to_users` — push to users | `push_to_users`
    pub async fn push_to_users(
        &self,
        login_ids: Vec<String>,
        content: String,
    ) -> SaTokenResult<()> {
        for login_id in login_ids {
            self.push_to_user(&login_id, content.clone()).await?;
        }
        Ok(())
    }

    /// Broadcast to all online users | 向全部在线用户广播
    pub async fn broadcast(&self, content: String) -> SaTokenResult<()> {
        let login_ids = self.get_online_users().await?;
        self.push_to_users(login_ids, content).await
    }

    /// `push_message_to_user` — push message to user | `push_message_to_user`
    pub async fn push_message_to_user(
        &self,
        login_id: &str,
        message: PushMessage,
    ) -> SaTokenResult<()> {
        let pushers = self.cloned_pushers().await;
        dispatch_to_pushers(&pushers, login_id, message).await
    }

    /// `kick_out_notify` — kick out notify | `kick_out_notify`
    pub async fn kick_out_notify(&self, login_id: &str, reason: String) -> SaTokenResult<()> {
        let message = PushMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            content: reason,
            message_type: MessageType::KickOut,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        };
        self.push_message_to_user(login_id, message).await?;
        self.mark_offline_all(login_id).await
    }
}

impl Default for OnlineManager {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory pusher for development.
/// 开发用内存推送器。
pub struct InMemoryPusher {
    messages: Arc<RwLock<HashMap<String, Vec<PushMessage>>>>,
}

impl std::fmt::Debug for InMemoryPusher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InMemoryPusher { .. }")
    }
}

impl InMemoryPusher {
    /// Create a new instance | 创建新实例
    pub fn new() -> Self {
        Self {
            messages: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// `get_messages` — get messages | `get_messages`
    pub async fn get_messages(&self, login_id: &str) -> Vec<PushMessage> {
        self.messages
            .read()
            .await
            .get(login_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Clear buffered messages for a login id (dev / tests).
    /// 清空某登录账号的缓冲消息（开发 / 测试）。
    pub async fn clear_messages(&self, login_id: &str) {
        self.messages.write().await.remove(login_id);
    }
}

impl Default for InMemoryPusher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MessagePusher for InMemoryPusher {
    async fn push(&self, login_id: &str, message: PushMessage) -> Result<(), SaTokenError> {
        self.messages
            .write()
            .await
            .entry(login_id.to_string())
            .or_default()
            .push(message);
        Ok(())
    }
}
