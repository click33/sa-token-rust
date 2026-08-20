// Author: 金书记 | Author: Jin Shuji
//! Online-user persistence: distributed (Dao) and process-local.
//! 在线用户持久化：分布式（Dao）与进程内。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::dao::SaTokenDao;
use crate::error::SaTokenResult;
use crate::keys::{LOGIN_TYPE_DEFAULT, SaKeys};
use crate::online::OnlineUser;

/// Snapshot written to storage.
/// 写入存储的在线用户快照。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOnlineUser {
    /// Account system | 账号体系
    #[serde(default = "default_login_type")]
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

fn default_login_type() -> String {
    LOGIN_TYPE_DEFAULT.to_string()
}

impl From<OnlineUser> for StoredOnlineUser {
    fn from(u: OnlineUser) -> Self {
        Self {
            login_type: u.login_type,
            login_id: u.login_id,
            token: u.token,
            device: u.device,
            connect_time: u.connect_time,
            last_activity: u.last_activity,
            metadata: u.metadata,
        }
    }
}

impl From<StoredOnlineUser> for OnlineUser {
    fn from(s: StoredOnlineUser) -> Self {
        OnlineUser {
            login_type: s.login_type,
            login_id: s.login_id,
            token: s.token,
            device: s.device,
            connect_time: s.connect_time,
            last_activity: s.last_activity,
            metadata: s.metadata,
        }
    }
}

/// Online store abstraction (inject Local in tests, Distributed in production).
/// 在线存储抽象（测试注入 Local，生产用 Distributed）。
#[async_trait]
pub trait OnlineStore: Send + Sync {
    /// Mark a user connection online | 标记用户连接在线
    async fn mark_online(&self, user: OnlineUser) -> SaTokenResult<()>;
    /// `mark_offline` — mark offline | `mark_offline`
    async fn mark_offline(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
    ) -> SaTokenResult<()>;
    /// Mark all connections offline | 标记该账号全部离线
    async fn mark_offline_all(&self, login_type: &str, login_id: &str) -> SaTokenResult<()>;
    /// Whether the login id is online | 登录 ID 是否在线
    async fn is_online(&self, login_type: &str, login_id: &str) -> SaTokenResult<bool>;
    /// `get_online_count` — get online count | `get_online_count`
    async fn get_online_count(&self) -> SaTokenResult<usize>;
    /// List online users for a login id | 列出某登录 ID 的在线用户
    async fn get_online_users(&self) -> SaTokenResult<Vec<String>>;
    /// `get_user_sessions` — get user sessions | `get_user_sessions`
    async fn get_user_sessions(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<OnlineUser>>;
    /// Refresh last-activity timestamp | 刷新最近活跃时间
    async fn update_activity(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
    ) -> SaTokenResult<()>;
    /// Drop index members whose record key is gone (TTL or crash).
    /// 丢掉记录键已消失的索引成员（TTL 或异常退出）。
    async fn prune_index(&self, login_type: &str, login_id: &str) -> SaTokenResult<usize>;
}

/// Shared store via SaTokenDao.
/// 经 SaTokenDao 的共享存储。
pub struct DistributedOnlineStore {
    dao: Arc<SaTokenDao>,
    /// Record TTL; None = follow token lifetime / no extra expire.
    /// 记录 TTL；None 表示不额外过期（依赖调用方登出清理）。
    entry_ttl: Option<Duration>,
}

impl std::fmt::Debug for DistributedOnlineStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DistributedOnlineStore { .. }")
    }
}

impl DistributedOnlineStore {
    /// Create a new instance | 创建新实例
    pub fn new(dao: Arc<SaTokenDao>, entry_ttl: Option<Duration>) -> Self {
        Self { dao, entry_ttl }
    }

    fn keys(&self) -> &SaKeys {
        self.dao.keys()
    }

    fn item_key(&self, login_type: &str, login_id: &str, token: &str) -> String {
        if SaKeys::is_default_login_type(login_type) {
            self.keys().online(login_id, token)
        } else {
            self.keys().online_with_type(login_type, login_id, token)
        }
    }

    fn index_key(&self, login_type: &str, login_id: &str) -> String {
        if SaKeys::is_default_login_type(login_type) {
            self.keys().online_index(login_id)
        } else {
            self.keys().online_index_with_type(login_type, login_id)
        }
    }
}

#[async_trait]
impl OnlineStore for DistributedOnlineStore {
    async fn mark_online(&self, user: OnlineUser) -> SaTokenResult<()> {
        let stored = StoredOnlineUser::from(user);
        let item_key = self.item_key(&stored.login_type, &stored.login_id, &stored.token);
        let idx_key = self.index_key(&stored.login_type, &stored.login_id);

        self.dao
            .set_object(&item_key, &stored, self.entry_ttl)
            .await?;
        // Atomic unique append — no read-modify-write race.
        // 原子去重追加，避免读改写丢失并发 token。
        self.dao
            .list_push_unique(&idx_key, &stored.token, self.entry_ttl)
            .await?;
        self.dao
            .list_push_unique(&self.keys().online_users_set(), &stored.login_id, None)
            .await?;
        Ok(())
    }

    async fn mark_offline(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
    ) -> SaTokenResult<()> {
        let item_key = self.item_key(login_type, login_id, token);
        let idx_key = self.index_key(login_type, login_id);
        self.dao.delete(&item_key).await?;
        self.dao.list_remove(&idx_key, token).await?;
        if self.dao.list_len(&idx_key).await? == 0 {
            self.dao.delete(&idx_key).await?;
            self.dao
                .list_remove(&self.keys().online_users_set(), login_id)
                .await?;
        }
        Ok(())
    }

    async fn mark_offline_all(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        let idx_key = self.index_key(login_type, login_id);
        let tokens = self.dao.list_range(&idx_key, 0, None).await?;
        for token in &tokens {
            let _ = self
                .dao
                .delete(&self.item_key(login_type, login_id, token))
                .await;
        }
        self.dao.delete(&idx_key).await?;
        self.dao
            .list_remove(&self.keys().online_users_set(), login_id)
            .await?;
        Ok(())
    }

    async fn is_online(&self, login_type: &str, login_id: &str) -> SaTokenResult<bool> {
        let sessions = self.get_user_sessions(login_type, login_id).await?;
        Ok(!sessions.is_empty())
    }

    async fn get_online_count(&self) -> SaTokenResult<usize> {
        self.dao.list_len(&self.keys().online_users_set()).await
    }

    async fn get_online_users(&self) -> SaTokenResult<Vec<String>> {
        self.dao
            .list_range(&self.keys().online_users_set(), 0, None)
            .await
    }

    async fn get_user_sessions(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<OnlineUser>> {
        let _ = self.prune_index(login_type, login_id).await;
        let idx_key = self.index_key(login_type, login_id);
        let tokens = self.dao.list_range(&idx_key, 0, None).await?;
        let mut out = Vec::with_capacity(tokens.len());
        for token in tokens {
            let key = self.item_key(login_type, login_id, &token);
            if let Some(stored) = self.dao.get_object::<StoredOnlineUser>(&key).await? {
                out.push(stored.into());
            }
        }
        Ok(out)
    }

    async fn update_activity(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
    ) -> SaTokenResult<()> {
        let key = self.item_key(login_type, login_id, token);
        if let Some(mut stored) = self.dao.get_object::<StoredOnlineUser>(&key).await? {
            stored.last_activity = Utc::now();
            self.dao.set_object(&key, &stored, self.entry_ttl).await?;
        }
        Ok(())
    }

    async fn prune_index(&self, login_type: &str, login_id: &str) -> SaTokenResult<usize> {
        let idx_key = self.index_key(login_type, login_id);
        let tokens = self.dao.list_range(&idx_key, 0, None).await?;
        let mut removed = 0usize;
        for token in &tokens {
            let key = self.item_key(login_type, login_id, token);
            if self.dao.get_string(&key).await?.is_none() {
                self.dao.list_remove(&idx_key, token).await?;
                removed += 1;
            }
        }
        if self.dao.list_len(&idx_key).await? == 0 {
            self.dao.delete(&idx_key).await?;
            self.dao
                .list_remove(&self.keys().online_users_set(), login_id)
                .await?;
        }
        Ok(removed)
    }
}

/// Process-local store (explicit single-node / tests).
/// 进程内存储（显式单机 / 测试）。
pub struct LocalOnlineStore {
    inner: Arc<RwLock<HashMap<String, Vec<OnlineUser>>>>,
}

impl std::fmt::Debug for LocalOnlineStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalOnlineStore { .. }")
    }
}

fn local_map_key(login_type: &str, login_id: &str) -> String {
    format!("{login_type}\u{1}{login_id}")
}

impl LocalOnlineStore {
    /// Create a new instance | 创建新实例
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for LocalOnlineStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OnlineStore for LocalOnlineStore {
    async fn mark_online(&self, user: OnlineUser) -> SaTokenResult<()> {
        let mut map = self.inner.write().await;
        let list = map
            .entry(local_map_key(&user.login_type, &user.login_id))
            .or_default();
        // Replace the same token instead of appending duplicates.
        // 同一 token 覆盖，避免重复会话。
        list.retain(|u| u.token != user.token);
        list.push(user);
        Ok(())
    }

    async fn mark_offline(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
    ) -> SaTokenResult<()> {
        let mut map = self.inner.write().await;
        let k = local_map_key(login_type, login_id);
        if let Some(list) = map.get_mut(&k) {
            list.retain(|u| u.token != token);
            if list.is_empty() {
                map.remove(&k);
            }
        }
        Ok(())
    }

    async fn mark_offline_all(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        self.inner
            .write()
            .await
            .remove(&local_map_key(login_type, login_id));
        Ok(())
    }

    async fn is_online(&self, login_type: &str, login_id: &str) -> SaTokenResult<bool> {
        let map = self.inner.read().await;
        Ok(map
            .get(&local_map_key(login_type, login_id))
            .is_some_and(|v| !v.is_empty()))
    }

    async fn get_online_count(&self) -> SaTokenResult<usize> {
        Ok(self.inner.read().await.len())
    }

    async fn get_online_users(&self) -> SaTokenResult<Vec<String>> {
        let map = self.inner.read().await;
        Ok(map
            .keys()
            .filter_map(|k| k.split('\u{1}').nth(1).map(str::to_string))
            .collect())
    }

    async fn get_user_sessions(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<OnlineUser>> {
        let map = self.inner.read().await;
        Ok(map
            .get(&local_map_key(login_type, login_id))
            .cloned()
            .unwrap_or_default())
    }

    async fn update_activity(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
    ) -> SaTokenResult<()> {
        let mut map = self.inner.write().await;
        if let Some(list) = map.get_mut(&local_map_key(login_type, login_id)) {
            if let Some(u) = list.iter_mut().find(|u| u.token == token) {
                u.last_activity = Utc::now();
            }
        }
        Ok(())
    }

    async fn prune_index(&self, _login_type: &str, _login_id: &str) -> SaTokenResult<usize> {
        Ok(0)
    }
}
