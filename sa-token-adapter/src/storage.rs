// Author: 金书记
//
//! 存储适配器 trait 定义

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// Storage operation result | 存储操作结果
pub type StorageResult<T> = Result<T, StorageError>;

/// Storage backend error | 存储后端错误
#[derive(Debug, Error)]
pub enum StorageError {
    /// Generic storage operation failure | 通用存储操作失败
    #[error("Storage operation failed: {0}")]
    OperationFailed(String),

    /// Key does not exist | 键不存在
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Value serialize/deserialize failed | 值序列化或反序列化失败
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Backend connection failure | 后端连接失败
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// Unexpected storage internal error | 未预期的存储内部错误
    #[error("Internal error: {0}")]
    InternalError(String),

    /// 当前存储后端尚未实现该操作（A1-8：携带操作名称，便于调试）
    #[error("Unsupported operation '{0}' on this storage backend")]
    Unsupported(&'static str),
}

/// 游标扫描的一页结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPage {
    /// 本页命中的逻辑键（不含 Redis 物理前缀）
    pub keys: Vec<String>,
    /// 下一页游标；为 0 表示遍历结束
    pub next_cursor: u64,
}

/// 存储适配器 trait
///
/// ## 键契约（A3）| Key Contract (A3)
///
/// - 所有方法的 `key` 参数均为 **逻辑键**（由 `SaKeys` 构造）；实现层不得再叠加第二层应用前缀，
///   除非显式配置为物理租户分区前缀（如 Redis `key_prefix`）。
/// - All `key` arguments are **logical keys** from `SaKeys`; implementations must not prepend
///   another application prefix unless configured as an optional physical partition.
///
/// 0.2.0 破坏性变更：删除 `keys()` 默认桩，统一改用 `scan` 分页扫描。
#[async_trait]
pub trait SaStorage: Send + Sync {
    /// Read value by key | 按键读取值
    async fn get(&self, key: &str) -> StorageResult<Option<String>>;
    /// Write value with optional TTL | 写入值（可选 TTL）
    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()>;
    /// Delete a key | 删除键
    async fn delete(&self, key: &str) -> StorageResult<()>;
    /// Whether the key exists | 键是否存在
    async fn exists(&self, key: &str) -> StorageResult<bool>;
    /// Update key TTL | 更新键过期时间
    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()>;
    /// Remaining TTL, if any | 剩余过期时间（若有）
    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>>;

    /// 批量读：默认逐键 get，具体后端可覆盖为 mget
    async fn mget(&self, keys: &[&str]) -> StorageResult<Vec<Option<String>>> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.get(key).await?);
        }
        Ok(results)
    }

    /// 批量写：默认逐键 set
    async fn mset(&self, items: &[(&str, &str)], ttl: Option<Duration>) -> StorageResult<()> {
        for (key, value) in items {
            self.set(key, value, ttl).await?;
        }
        Ok(())
    }

    /// 批量删：默认逐键 delete
    async fn mdel(&self, keys: &[&str]) -> StorageResult<()> {
        for key in keys {
            self.delete(key).await?;
        }
        Ok(())
    }

    /// 自增：**默认实现非原子**（读-改-写），并发环境下计数不准确
    ///
    /// 【A1-1 警告】MemoryStorage / RedisStorage 应覆盖此方法，提供原子递增语义。
    async fn incr(&self, key: &str) -> StorageResult<i64> {
        let current = self
            .get(key)
            .await?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        let new_value = current + 1;
        self.set(key, &new_value.to_string(), None).await?;
        Ok(new_value)
    }

    /// 自减：**默认实现非原子**（读-改-写），语义同 incr
    ///
    /// 【A1-1 警告】MemoryStorage / RedisStorage 应覆盖此方法。
    async fn decr(&self, key: &str) -> StorageResult<i64> {
        let current = self
            .get(key)
            .await?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        let new_value = current - 1;
        self.set(key, &new_value.to_string(), None).await?;
        Ok(new_value)
    }

    /// Remove all keys | 清空全部键
    async fn clear(&self) -> StorageResult<()>;

    /// 仅当键不存在（或已过期）时写入；成功占位返回 true
    ///
    /// 用途：nonce 占位、分布式锁
    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool>;

    /// 读取并删除；保证单次消费者语义
    ///
    /// 用途：nonce 一次性消费、ticket 消费
    async fn get_del(&self, key: &str) -> StorageResult<Option<String>>;

    /// 比较并交换：当且仅当当前值等于 `expected` 时，写入 `new_value`
    ///
    /// 【A1-7 语义明确】：
    /// - `expected = None`：期望键**不存在或已过期**（首次写入语义）
    /// - `expected = Some("old")`：期望键当前值为 `"old"`（乐观更新语义）
    ///
    /// 返回 `true` 表示 CAS 成功（值已更新），`false` 表示期望不匹配（值未修改）
    ///
    /// 用途：token 索引 / 权限列表的 JSON 乐观更新
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool>;

    /// 比较并删除：仅当当前值等于 expected 时删除
    ///
    /// 返回 `true` 表示删除成功，`false` 表示期望不匹配（键未删除）
    async fn compare_and_delete(&self, key: &str, expected: &str) -> StorageResult<bool>;

    /// 向集合追加成员；unique=true 时跳过重复项
    ///
    /// 【A1-2】RedisStorage 使用 Lua 原子去重版本，保证 unique 并发安全。
    ///
    /// 用途：多设备 token 索引、权限列表
    async fn list_push(
        &self,
        key: &str,
        member: &str,
        unique: bool,
        ttl: Option<Duration>,
    ) -> StorageResult<usize>;

    /// 从集合移除成员；返回是否确实移除
    async fn list_remove(&self, key: &str, member: &str) -> StorageResult<bool>;

    /// 分页读取集合成员
    ///
    /// 【A1-5 注意】MemoryStorage 在键过期后返回空列表（不返回过期数据）
    async fn list_range(
        &self,
        key: &str,
        start: usize,
        limit: Option<usize>,
    ) -> StorageResult<Vec<String>>;

    /// 集合长度
    ///
    /// 【A1-5 注意】MemoryStorage 在键过期后返回 0
    async fn list_len(&self, key: &str) -> StorageResult<usize>;

    /// 游标扫描：pattern 为 glob（`*` / `?`），cursor 为上一页 next_cursor
    ///
    /// - `pattern` 为逻辑键 glob（由 `SaKeys::scan_pattern` 等构造）
    /// - 返回的 `ScanPage::keys` 均为逻辑键（Redis 实现会剥离物理前缀）
    /// - `limit` 为**每页建议条数**；Redis SCAN 的 COUNT 仅为提示，实现可返回更多匹配项
    /// - 仅扫描标量键命名空间；列表键（`list:` 前缀）会被排除
    ///
    /// 【A1-9 一致性保证差异】：
    /// - **MemoryStorage**：强一致性，单次 scan 内不会返回重复键，并发插入可能跳过新键
    /// - **RedisStorage**：弱一致性（Redis SCAN 语义），可能返回重复键、遗漏或额外包含并发修改的键
    ///
    /// 【A1-3/A1-4 性能与并发】：
    /// - MemoryStorage 每次全量排序，10w+ 键时延迟高（仅开发/测试场景）
    /// - MemoryStorage 并发修改时游标可能跳过或重复（文档标注非生产）
    ///
    /// 用途：logout_by_login_id 回退扫描、批量过期键清理
    async fn scan(&self, pattern: &str, cursor: u64, limit: usize) -> StorageResult<ScanPage>;
}

/// 分页扫描直到结束，聚合全部匹配键
///
/// 【A1-9 弱一致性处理】：RedisStorage 可能返回重复键，此函数**不自动去重**。
/// 如需去重，调用 [`scan_all_keys_dedup`]。
pub async fn scan_all_keys(
    storage: &dyn SaStorage,
    pattern: &str,
    page_size: usize,
) -> StorageResult<Vec<String>> {
    let mut cursor = 0u64;
    let mut all = Vec::new();
    loop {
        let page = storage.scan(pattern, cursor, page_size).await?;
        all.extend(page.keys);
        if page.next_cursor == 0 {
            break;
        }
        cursor = page.next_cursor;
    }
    Ok(all)
}

/// 分页扫描直到结束，聚合全部匹配键并去重
///
/// 【A1-9 补充】：应对 Redis SCAN 的弱一致性，自动去重。
pub async fn scan_all_keys_dedup(
    storage: &dyn SaStorage,
    pattern: &str,
    page_size: usize,
) -> StorageResult<Vec<String>> {
    use std::collections::HashSet;
    let all = scan_all_keys(storage, pattern, page_size).await?;
    let deduped: Vec<String> = all
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    Ok(deduped)
}
