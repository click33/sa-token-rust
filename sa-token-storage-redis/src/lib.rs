// Author: 金书记
//
//! # sa-token-storage-redis
//!
//! Redis存储实现
//!
//! 适用于：
//! - 分布式部署
//! - 需要数据持久化
//! - 高性能要求的场景
//!
//! ## 使用方式
//!
//! ### 方式 1: 使用 Redis URL
//! ```rust,ignore
//! use sa_token_storage_redis::RedisStorage;
//!
//! // 无密码
//! let storage = RedisStorage::new("redis://localhost:6379/0", "sa-token:").await?;
//!
//! // 有密码
//! let storage = RedisStorage::new("redis://:password@localhost:6379/0", "sa-token:").await?;
//! ```
//!
//! ### 方式 2: 使用配置结构体
//! ```rust,ignore
//! use sa_token_storage_redis::{RedisStorage, RedisConfig};
//!
//! let config = RedisConfig {
//!     host: "localhost".to_string(),
//!     port: 6379,
//!     password: Some("your-password".to_string()),
//!     database: 0,
//!     pool_size: 10,
//! };
//!
//! let storage = RedisStorage::from_config(config, "sa-token:").await?;
//! ```

use async_trait::async_trait;
use redis::{AsyncCommands, Client, aio::ConnectionManager};
use sa_token_adapter::storage::{SaStorage, ScanPage, StorageError, StorageResult};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Redis 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis 主机地址
    #[serde(default = "default_host")]
    pub host: String,

    /// Redis 端口
    #[serde(default = "default_port")]
    pub port: u16,

    /// Redis 密码（可选）
    #[serde(default)]
    pub password: Option<String>,

    /// 数据库编号
    #[serde(default)]
    pub database: u8,

    /// 连接池大小（暂未使用，保留用于未来扩展）
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            password: None,
            database: 0,
            pool_size: default_pool_size(),
        }
    }
}

impl RedisConfig {
    /// 转换为 Redis URL
    ///
    /// 支持的格式：
    /// - `redis://localhost:6379/0` （无密码）
    /// - `redis://:password@localhost:6379/0` （有密码）
    pub fn to_url(&self) -> String {
        if let Some(password) = &self.password {
            format!(
                "redis://:{}@{}:{}/{}",
                password, self.host, self.port, self.database
            )
        } else {
            format!("redis://{}:{}/{}", self.host, self.port, self.database)
        }
    }
}

fn default_host() -> String {
    "localhost".to_string()
}

fn default_port() -> u16 {
    6379
}

fn default_pool_size() -> u32 {
    10
}

/// Redis存储实现
#[derive(Clone)]
pub struct RedisStorage {
    client: ConnectionManager,
    key_prefix: String,
}

impl std::fmt::Debug for RedisStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStorage")
            .field("key_prefix", &self.key_prefix)
            .finish_non_exhaustive()
    }
}

impl RedisStorage {
    /// 使用 Redis URL 创建存储
    ///
    /// # 参数
    /// * `redis_url` - Redis 连接 URL
    /// * `key_prefix` - 键前缀（例如：`sa-token:`）
    ///
    /// # URL 格式
    /// - 无密码：`redis://localhost:6379/0`
    /// - 有密码：`redis://:password@localhost:6379/0`
    /// - 复杂密码：`redis://:Aq23-hjPwFB3mBDNFp3W1@localhost:6379/0`
    ///
    /// # 示例
    /// ```rust,ignore
    /// use sa_token_storage_redis::RedisStorage;
    ///
    /// // 无密码
    /// let storage = RedisStorage::new("redis://localhost:6379/0", "sa-token:").await?;
    ///
    /// // 有密码
    /// let storage = RedisStorage::new(
    ///     "redis://:Aq23-hjPwFB3mBDNFp3W1@localhost:6379/0",
    ///     "sa-token:"
    /// ).await?;
    /// ```
    pub async fn new(redis_url: &str, key_prefix: impl Into<String>) -> StorageResult<Self> {
        let client =
            Client::open(redis_url).map_err(|e| StorageError::ConnectionError(e.to_string()))?;

        let connection_manager = ConnectionManager::new(client)
            .await
            .map_err(|e| StorageError::ConnectionError(e.to_string()))?;

        Ok(Self {
            client: connection_manager,
            key_prefix: key_prefix.into(),
        })
    }

    /// 使用配置结构体创建存储
    ///
    /// # 参数
    /// * `config` - Redis 配置
    /// * `key_prefix` - 键前缀（例如：`sa-token:`）
    ///
    /// # 示例
    /// ```rust,ignore
    /// use sa_token_storage_redis::{RedisStorage, RedisConfig};
    ///
    /// let config = RedisConfig {
    ///     host: "localhost".to_string(),
    ///     port: 6379,
    ///     password: Some("Aq23-hjPwFB3mBDNFp3W1".to_string()),
    ///     database: 0,
    ///     pool_size: 10,
    /// };
    ///
    /// let storage = RedisStorage::from_config(config, "sa-token:").await?;
    /// ```
    pub async fn from_config(
        config: RedisConfig,
        key_prefix: impl Into<String>,
    ) -> StorageResult<Self> {
        let redis_url = config.to_url();
        Self::new(&redis_url, key_prefix).await
    }

    /// 使用构建器模式创建存储
    ///
    /// # 示例
    /// ```rust,ignore
    /// use sa_token_storage_redis::RedisStorage;
    ///
    /// let storage = RedisStorage::builder()
    ///     .host("localhost")
    ///     .port(6379)
    ///     .password("Aq23-hjPwFB3mBDNFp3W1")
    ///     .database(0)
    ///     .key_prefix("sa-token:")
    ///     .build()
    ///     .await?;
    /// ```
    pub fn builder() -> RedisStorageBuilder {
        RedisStorageBuilder::default()
    }

    /// 获取完整的键名（带前缀）
    fn full_key(&self, key: &str) -> String {
        format!("{}{}", self.key_prefix, key)
    }

    /// 列表键使用独立前缀，避免与字符串键类型冲突
    fn list_key(&self, key: &str) -> String {
        format!("{}list:{}", self.key_prefix, key)
    }

    /// 将物理键剥离为逻辑键；前缀不匹配时返回 `None`
    fn strip_prefix<'a>(&self, raw: &'a str) -> Option<&'a str> {
        raw.strip_prefix(&self.key_prefix)
    }

    /// 便捷构造：物理前缀默认为空（逻辑键由 SaKeys 提供）
    pub async fn connect(redis_url: &str) -> StorageResult<Self> {
        Self::new(redis_url, "").await
    }
}

/// Redis 存储构建器
#[derive(Default)]
pub struct RedisStorageBuilder {
    config: RedisConfig,
    key_prefix: Option<String>,
}

impl std::fmt::Debug for RedisStorageBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStorageBuilder")
            .field("key_prefix", &self.key_prefix)
            .finish_non_exhaustive()
    }
}

impl RedisStorageBuilder {
    /// 设置 Redis 主机地址
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.config.host = host.into();
        self
    }

    /// 设置 Redis 端口
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// 设置 Redis 密码
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.config.password = Some(password.into());
        self
    }

    /// 设置数据库编号
    pub fn database(mut self, database: u8) -> Self {
        self.config.database = database;
        self
    }

    /// 设置连接池大小（保留用于未来扩展）
    pub fn pool_size(mut self, size: u32) -> Self {
        self.config.pool_size = size;
        self
    }

    /// 设置键前缀
    pub fn key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = Some(prefix.into());
        self
    }

    /// 构建 RedisStorage（未设置 `key_prefix` 时默认为空字符串）
    pub async fn build(self) -> StorageResult<RedisStorage> {
        let key_prefix = self.key_prefix.unwrap_or_default();
        RedisStorage::from_config(self.config, key_prefix).await
    }
}

#[async_trait]
impl SaStorage for RedisStorage {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.get(&full_key)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        if let Some(ttl) = ttl {
            conn.set_ex(&full_key, value, ttl.as_secs())
                .await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))
        } else {
            conn.set(&full_key, value)
                .await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))
        }
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.del(&full_key)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.exists(&full_key)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.expire(&full_key, ttl.as_secs() as i64)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        let ttl_secs: i64 = conn
            .ttl(&full_key)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        match ttl_secs {
            -2 => Ok(None), // 键不存在
            -1 => Ok(None), // 永不过期
            secs if secs > 0 => Ok(Some(Duration::from_secs(secs as u64))),
            _ => Ok(Some(Duration::from_secs(0))),
        }
    }

    async fn mget(&self, keys: &[&str]) -> StorageResult<Vec<Option<String>>> {
        let mut conn = self.client.clone();
        let full_keys: Vec<String> = keys.iter().map(|k| self.full_key(k)).collect();

        // redis 1.x 的 `get` 只接受 ToSingleRedisArg，批量取值需走 `mget`
        // redis 1.x's `get` only accepts ToSingleRedisArg; use `mget` for multi-key reads
        conn.mget(&full_keys)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn mset(&self, items: &[(&str, &str)], ttl: Option<Duration>) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_items: Vec<(String, &str)> =
            items.iter().map(|(k, v)| (self.full_key(k), *v)).collect();

        // 使用 pipeline 批量操作
        let mut pipe = redis::pipe();
        for (key, value) in &full_items {
            if let Some(ttl) = ttl {
                pipe.set_ex(key, *value, ttl.as_secs());
            } else {
                pipe.set(key, *value);
            }
        }

        pipe.query_async(&mut conn)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn mdel(&self, keys: &[&str]) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_keys: Vec<String> = keys.iter().map(|k| self.full_key(k)).collect();

        conn.del(&full_keys)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn incr(&self, key: &str) -> StorageResult<i64> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.incr(&full_key, 1)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn decr(&self, key: &str) -> StorageResult<i64> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.decr(&full_key, 1)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn clear(&self) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let pattern = format!("{}*", self.key_prefix);
        let mut cursor: u64 = 0;

        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

            if !keys.is_empty() {
                conn.del::<_, ()>(&keys)
                    .await
                    .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
            }

            if next == 0 {
                break;
            }
            cursor = next;
        }

        Ok(())
    }

    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        let inserted: bool = if let Some(ttl) = ttl {
            redis::cmd("SET")
                .arg(&full_key)
                .arg(value)
                .arg("NX")
                .arg("EX")
                .arg(ttl.as_secs())
                .query_async(&mut conn)
                .await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?
        } else {
            conn.set_nx(&full_key, value)
                .await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?
        };

        Ok(inserted)
    }

    async fn get_del(&self, key: &str) -> StorageResult<Option<String>> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        let value: Option<String> = redis::cmd("GETDEL")
            .arg(&full_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        Ok(value)
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);
        let expected_str = expected.unwrap_or("");
        let ttl_secs = ttl.map(|d| d.as_secs()).unwrap_or(0);

        // Lua 保证 GET + 比较 + SET 单键原子，避免 WATCH 竞态。
        // expected=None 时 ARGV[1] 为空串：键不存在（GET 返回 false）视为匹配。
        let script = r#"
            local current = redis.call('GET', KEYS[1])
            if current == false then current = '' end
            if current ~= ARGV[1] then return 0 end
            if tonumber(ARGV[3]) > 0 then
                redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
            else
                redis.call('SET', KEYS[1], ARGV[2])
            end
            return 1
        "#;

        let swapped: i32 = redis::Script::new(script)
            .key(&full_key)
            .arg(expected_str)
            .arg(new_value)
            .arg(ttl_secs)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        Ok(swapped == 1)
    }

    async fn compare_and_delete(&self, key: &str, expected: &str) -> StorageResult<bool> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        let script = r#"
            local current = redis.call('GET', KEYS[1])
            if current == false then current = '' end
            if current ~= ARGV[1] then return 0 end
            redis.call('DEL', KEYS[1])
            return 1
        "#;

        let deleted: i32 = redis::Script::new(script)
            .key(&full_key)
            .arg(expected)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        Ok(deleted == 1)
    }

    async fn list_push(
        &self,
        key: &str,
        member: &str,
        unique: bool,
        ttl: Option<Duration>,
    ) -> StorageResult<usize> {
        // 【A1-2】Lua 原子去重：LRANGE + 判断 + RPUSH + EXPIRE 在同一脚本内完成
        let mut conn = self.client.clone();
        let list_key = self.list_key(key);
        let ttl_secs = ttl.map(|d| d.as_secs()).unwrap_or(0);

        let script = r#"
            local list_key = KEYS[1]
            local member = ARGV[1]
            local unique = tonumber(ARGV[2])
            local ttl_secs = tonumber(ARGV[3])

            if unique == 1 then
                local items = redis.call('LRANGE', list_key, 0, -1)
                for i, v in ipairs(items) do
                    if v == member then
                        if ttl_secs > 0 then
                            redis.call('EXPIRE', list_key, ttl_secs)
                        end
                        return #items
                    end
                end
            end

            local len = redis.call('RPUSH', list_key, member)
            if ttl_secs > 0 then
                redis.call('EXPIRE', list_key, ttl_secs)
            end
            return len
        "#;

        let len: usize = redis::Script::new(script)
            .key(&list_key)
            .arg(member)
            .arg(if unique { 1 } else { 0 })
            .arg(ttl_secs)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        Ok(len)
    }

    async fn list_remove(&self, key: &str, member: &str) -> StorageResult<bool> {
        let mut conn = self.client.clone();
        let list_key = self.list_key(key);

        let removed: i64 = conn
            .lrem(&list_key, 0, member)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        Ok(removed > 0)
    }

    async fn list_range(
        &self,
        key: &str,
        start: usize,
        limit: Option<usize>,
    ) -> StorageResult<Vec<String>> {
        let mut conn = self.client.clone();
        let list_key = self.list_key(key);
        let stop = match limit {
            Some(l) => {
                let end = start.saturating_add(l).saturating_sub(1);
                isize::try_from(end.min(isize::MAX as usize)).unwrap_or(isize::MAX)
            }
            None => -1,
        };

        conn.lrange(&list_key, start as isize, stop)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn list_len(&self, key: &str) -> StorageResult<usize> {
        let mut conn = self.client.clone();
        let list_key = self.list_key(key);

        let len: i64 = conn
            .llen(&list_key)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        Ok(len.max(0) as usize)
    }

    async fn scan(&self, pattern: &str, cursor: u64, limit: usize) -> StorageResult<ScanPage> {
        let mut conn = self.client.clone();
        let full_pattern = self.full_key(pattern);

        let (next, raw_keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&full_pattern)
            .arg("COUNT")
            .arg(limit.max(1))
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        let list_prefix = format!("{}list:", self.key_prefix);
        let keys: Vec<String> = raw_keys
            .into_iter()
            .filter(|k| !k.starts_with(&list_prefix))
            .filter_map(|k| self.strip_prefix(&k).map(str::to_string))
            .collect();

        Ok(ScanPage {
            keys,
            next_cursor: next,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_adapter::storage::SaStorage;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_logical_key_stripping_matches_manager_expectations() {
        let prefix = "phys:";
        let raw = vec!["phys:sa:token:a".to_string(), "phys:sa:token:b".to_string()];
        let n = prefix.len();
        let logical: Vec<String> = raw
            .into_iter()
            .map(|k| k.get(n..).map(str::to_string).unwrap_or(k))
            .collect();
        assert_eq!(logical, vec!["sa:token:a", "sa:token:b"]);
    }

    /// 真实 Redis：无 REDIS_URL 时 ignore；测 set/get/ttl/get_del。
    #[tokio::test]
    #[ignore = "requires REDIS_URL"]
    async fn test_redis_set_get_ttl_get_del() {
        let url = std::env::var("REDIS_URL").expect("REDIS_URL");
        let storage = RedisStorage::connect(&url).await.expect("connect");
        let storage: Arc<dyn SaStorage> = Arc::new(storage);
        let key = format!(
            "sa:test:gray:{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        );
        storage
            .set(&key, "v1", Some(Duration::from_secs(30)))
            .await
            .expect("set");
        assert_eq!(
            storage.get(&key).await.expect("get").as_deref(),
            Some("v1")
        );
        let ttl = storage.ttl(&key).await.expect("ttl");
        assert!(ttl.is_some());
        let secs = ttl.unwrap().as_secs();
        assert!(secs > 0 && secs <= 30);
        let taken = storage.get_del(&key).await.expect("get_del");
        assert_eq!(taken.as_deref(), Some("v1"));
        assert!(storage.get(&key).await.expect("gone").is_none());
    }
}
