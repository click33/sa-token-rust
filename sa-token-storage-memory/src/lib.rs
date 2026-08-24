// Author: 金书记
//
//! 内存存储实现（开发/单机/无持久化场景）

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sa_token_adapter::storage::{SaStorage, ScanPage, StorageError, StorageResult};
use tokio::sync::RwLock;

/// 分片数：2 的幂，用位与代替取模。同一 key 的标量与 list 必须落在同一分片。
/// Shard count (power of two). Scalar and list for the same key must share a shard.
const SHARD_COUNT: usize = 16;
const SHARD_MASK: usize = SHARD_COUNT - 1;

/// 标量键值项
#[derive(Debug, Clone)]
struct StorageItem {
    value: String,
    expire_at: Option<DateTime<Utc>>,
}

impl StorageItem {
    fn new(value: String, ttl: Option<Duration>) -> Self {
        let expire_at = ttl
            .and_then(|d| chrono::Duration::from_std(d).ok())
            .map(|d| Utc::now() + d);
        Self { value, expire_at }
    }

    fn is_expired(&self) -> bool {
        self.expire_at.is_some_and(|t| Utc::now() > t)
    }
}

/// 集合键项
#[derive(Debug, Clone, Default)]
struct ListItem {
    members: Vec<String>,
    expire_at: Option<DateTime<Utc>>,
}

impl ListItem {
    fn touch_ttl(&mut self, ttl: Option<Duration>) {
        if let Some(d) = ttl.and_then(|d| chrono::Duration::from_std(d).ok()) {
            self.expire_at = Some(Utc::now() + d);
        }
    }

    fn is_expired(&self) -> bool {
        self.expire_at.is_some_and(|t| Utc::now() > t)
    }
}

/// 单分片状态（同 key 的 scalar / list 同锁）
/// Per-shard state (scalar and list for one key share the lock)
#[derive(Debug, Default)]
struct MemoryState {
    scalars: HashMap<String, StorageItem>,
    lists: HashMap<String, ListItem>,
}

/// 将 glob 风格 pattern 转为锚定正则（转义元字符，`*` → `.*`）
///
/// 修复 1.2-E：旧版 `pattern.replace("*", ".*")` 未锚定，导致 `sa:token:*` 误匹配 `x-sa:token:y`
fn glob_to_regex(pattern: &str) -> Result<regex::Regex, StorageError> {
    let mut re = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c if ".^$+{}[]|()\\".contains(c) => {
                re.push('\\');
                re.push(c);
            }
            c => re.push(c),
        }
    }
    re.push('$');
    regex::Regex::new(&re)
        .map_err(|e| StorageError::OperationFailed(format!("Invalid pattern: {e}")))
}

/// 内部可控 key 用 FNV-1a；不引入 ahash。
/// FNV-1a for library-controlled keys; no ahash dependency.
#[inline]
fn shard_index(key: &str) -> usize {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash as usize) & SHARD_MASK
}

/// In-memory [`SaStorage`] for tests and single-node use.
/// 进程内内存存储，适用于测试与单机场景。
#[derive(Debug, Clone)]
pub struct MemoryStorage {
    shards: Arc<[RwLock<MemoryState>]>,
}

impl MemoryStorage {
    /// Create an empty memory store | 创建空的内存存储
    pub fn new() -> Self {
        let shards: Vec<_> = (0..SHARD_COUNT)
            .map(|_| RwLock::new(MemoryState::default()))
            .collect();
        Self {
            shards: shards.into(),
        }
    }

    #[inline]
    fn shard(&self, key: &str) -> &RwLock<MemoryState> {
        // `shard_index` is masked to `0..SHARD_COUNT`; get avoids clippy::indexing_slicing.
        // `shard_index` 经掩码落在 `0..SHARD_COUNT`；用 get 规避 indexing_slicing。
        match self.shards.get(shard_index(key)) {
            Some(s) => s,
            None => unreachable!("shard_index always in 0..SHARD_COUNT"),
        }
    }

    /// 清理过期标量与集合（逐分片写锁，禁止同时持多把写锁）
    /// Drop expired scalars/lists (one write lock at a time; never hold multiple)
    pub async fn cleanup_expired(&self) {
        for shard in self.shards.iter() {
            let mut s = shard.write().await;
            s.scalars.retain(|_, v| !v.is_expired());
            s.lists.retain(|_, v| !v.is_expired());
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SaStorage for MemoryStorage {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        let s = self.shard(key).read().await;
        match s.scalars.get(key) {
            Some(item) if !item.is_expired() => Ok(Some(item.value.clone())),
            Some(_) => {
                drop(s);
                self.delete(key).await?;
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()> {
        let mut s = self.shard(key).write().await;
        s.scalars
            .insert(key.to_string(), StorageItem::new(value.to_string(), ttl));
        Ok(())
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let mut s = self.shard(key).write().await;
        s.scalars.remove(key);
        s.lists.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let s = self.shard(key).read().await;
        if let Some(item) = s.scalars.get(key) {
            return Ok(!item.is_expired());
        }
        if let Some(list) = s.lists.get(key) {
            return Ok(!list.is_expired() && !list.members.is_empty());
        }
        Ok(false)
    }

    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()> {
        let mut s = self.shard(key).write().await;
        let Some(delta) = chrono::Duration::from_std(ttl).ok() else {
            return Ok(());
        };
        let exp = Utc::now() + delta;
        if let Some(item) = s.scalars.get_mut(key) {
            item.expire_at = Some(exp);
        }
        if let Some(list) = s.lists.get_mut(key) {
            list.expire_at = Some(exp);
        }
        Ok(())
    }

    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>> {
        let s = self.shard(key).read().await;
        let expire_at = s
            .scalars
            .get(key)
            .and_then(|i| i.expire_at)
            .or_else(|| s.lists.get(key).and_then(|l| l.expire_at));
        match expire_at {
            Some(exp) if exp > Utc::now() => Ok(Some(
                (exp - Utc::now())
                    .to_std()
                    .map_err(|e| StorageError::InternalError(e.to_string()))?,
            )),
            Some(_) => Ok(Some(Duration::ZERO)),
            None => Ok(None),
        }
    }

    /// 批量读：按 key 分片取，不跨分片持锁。
    /// Batched get: lock per key's shard; never hold multiple shard locks.
    async fn mget(&self, keys: &[&str]) -> StorageResult<Vec<Option<String>>> {
        let mut results = Vec::with_capacity(keys.len());
        for &key in keys {
            results.push(self.get(key).await?);
        }
        Ok(results)
    }

    async fn mset(&self, items: &[(&str, &str)], ttl: Option<Duration>) -> StorageResult<()> {
        for (key, value) in items {
            self.set(key, value, ttl).await?;
        }
        Ok(())
    }

    async fn mdel(&self, keys: &[&str]) -> StorageResult<()> {
        for key in keys {
            self.delete(key).await?;
        }
        Ok(())
    }

    async fn incr(&self, key: &str) -> StorageResult<i64> {
        let mut s = self.shard(key).write().await;
        let current = s
            .scalars
            .get(key)
            .filter(|item| !item.is_expired())
            .and_then(|item| item.value.parse::<i64>().ok())
            .unwrap_or(0);
        let new_value = current + 1;
        s.scalars.insert(
            key.to_string(),
            StorageItem::new(new_value.to_string(), None),
        );
        Ok(new_value)
    }

    async fn decr(&self, key: &str) -> StorageResult<i64> {
        let mut s = self.shard(key).write().await;
        let current = s
            .scalars
            .get(key)
            .filter(|item| !item.is_expired())
            .and_then(|item| item.value.parse::<i64>().ok())
            .unwrap_or(0);
        let new_value = current - 1;
        s.scalars.insert(
            key.to_string(),
            StorageItem::new(new_value.to_string(), None),
        );
        Ok(new_value)
    }

    async fn clear(&self) -> StorageResult<()> {
        for shard in self.shards.iter() {
            let mut s = shard.write().await;
            s.scalars.clear();
            s.lists.clear();
        }
        Ok(())
    }

    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        let mut s = self.shard(key).write().await;
        if let Some(existing) = s.scalars.get(key) {
            if !existing.is_expired() {
                return Ok(false);
            }
            s.scalars.remove(key);
        }
        s.scalars
            .insert(key.to_string(), StorageItem::new(value.to_string(), ttl));
        Ok(true)
    }

    async fn get_del(&self, key: &str) -> StorageResult<Option<String>> {
        let mut s = self.shard(key).write().await;
        match s.scalars.remove(key) {
            Some(item) if !item.is_expired() => Ok(Some(item.value)),
            _ => Ok(None),
        }
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        let mut s = self.shard(key).write().await;
        let current = s
            .scalars
            .get(key)
            .filter(|i| !i.is_expired())
            .map(|i| i.value.as_str());
        if current != expected {
            return Ok(false);
        }
        s.scalars.insert(
            key.to_string(),
            StorageItem::new(new_value.to_string(), ttl),
        );
        Ok(true)
    }

    async fn compare_and_delete(&self, key: &str, expected: &str) -> StorageResult<bool> {
        let mut s = self.shard(key).write().await;
        let ok = s
            .scalars
            .get(key)
            .filter(|i| !i.is_expired())
            .is_some_and(|i| i.value == expected);
        if ok {
            s.scalars.remove(key);
        }
        Ok(ok)
    }

    async fn list_push(
        &self,
        key: &str,
        member: &str,
        unique: bool,
        ttl: Option<Duration>,
    ) -> StorageResult<usize> {
        let mut s = self.shard(key).write().await;
        let entry = s.lists.entry(key.to_string()).or_default();
        if entry.is_expired() {
            entry.members.clear();
            entry.expire_at = None;
        }
        if unique && entry.members.iter().any(|m| m == member) {
            entry.touch_ttl(ttl);
            return Ok(entry.members.len());
        }
        entry.members.push(member.to_string());
        entry.touch_ttl(ttl);
        Ok(entry.members.len())
    }

    async fn list_remove(&self, key: &str, member: &str) -> StorageResult<bool> {
        let mut s = self.shard(key).write().await;
        let Some(entry) = s.lists.get_mut(key) else {
            return Ok(false);
        };
        if entry.is_expired() {
            entry.members.clear();
            return Ok(false);
        }
        let before = entry.members.len();
        entry.members.retain(|m| m != member);
        Ok(entry.members.len() < before)
    }

    async fn list_range(
        &self,
        key: &str,
        start: usize,
        limit: Option<usize>,
    ) -> StorageResult<Vec<String>> {
        let s = self.shard(key).read().await;
        let Some(entry) = s.lists.get(key) else {
            return Ok(Vec::new());
        };
        if entry.is_expired() {
            return Ok(Vec::new());
        }
        let slice: Vec<String> = entry
            .members
            .iter()
            .skip(start)
            .take(limit.unwrap_or(usize::MAX))
            .cloned()
            .collect();
        Ok(slice)
    }

    async fn list_len(&self, key: &str) -> StorageResult<usize> {
        let s = self.shard(key).read().await;
        Ok(s.lists
            .get(key)
            .filter(|l| !l.is_expired())
            .map(|l| l.members.len())
            .unwrap_or(0))
    }

    async fn scan(&self, pattern: &str, cursor: u64, limit: usize) -> StorageResult<ScanPage> {
        let re = glob_to_regex(pattern)?;
        // 逐分片读锁收集，禁止同时持多把锁。
        // Collect under one shard read lock at a time.
        let mut keys: Vec<String> = Vec::new();
        for shard in self.shards.iter() {
            let s = shard.read().await;
            for (k, v) in s.scalars.iter() {
                if !v.is_expired() {
                    keys.push(k.clone());
                }
            }
        }
        keys.sort();
        keys.dedup();
        keys.retain(|k| re.is_match(k));
        let start = cursor as usize;
        if start >= keys.len() {
            return Ok(ScanPage {
                keys: Vec::new(),
                next_cursor: 0,
            });
        }
        let end = (start + limit).min(keys.len());
        let page_keys = keys.get(start..end).unwrap_or(&[]).to_vec();
        let next = if end >= keys.len() { 0 } else { end as u64 };
        Ok(ScanPage {
            keys: page_keys,
            next_cursor: next,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_adapter::CountingStorage;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_set_if_absent_and_get_del() {
        let storage = MemoryStorage::new();
        assert!(storage.set_if_absent("n1", "v", None).await.unwrap());
        assert!(!storage.set_if_absent("n1", "v2", None).await.unwrap());
        assert_eq!(storage.get_del("n1").await.unwrap(), Some("v".into()));
        assert_eq!(storage.get_del("n1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_concurrent_nonce_get_del() {
        let storage = Arc::new(MemoryStorage::new());
        storage.set_if_absent("nonce:x", "1", None).await.unwrap();
        let mut got = 0usize;
        for _ in 0..100 {
            if storage.get_del("nonce:x").await.unwrap().is_some() {
                got += 1;
            }
        }
        assert_eq!(got, 1);
    }

    #[tokio::test]
    async fn test_compare_and_swap_and_delete() {
        let storage = MemoryStorage::new();
        storage.set("k", "old", None).await.unwrap();
        assert!(
            !storage
                .compare_and_swap("k", Some("wrong"), "new", None)
                .await
                .unwrap()
        );
        assert_eq!(storage.get("k").await.unwrap(), Some("old".into()));
        assert!(
            storage
                .compare_and_swap("k", Some("old"), "new", None)
                .await
                .unwrap()
        );
        assert_eq!(storage.get("k").await.unwrap(), Some("new".into()));
        assert!(!storage.compare_and_delete("k", "wrong").await.unwrap());
        assert!(storage.compare_and_delete("k", "new").await.unwrap());
        assert!(!storage.exists("k").await.unwrap());
    }

    #[tokio::test]
    async fn test_concurrent_list_push() {
        let storage = Arc::new(MemoryStorage::new());
        let mut handles = Vec::new();
        for i in 0..50 {
            let s = Arc::clone(&storage);
            handles.push(tokio::spawn(async move {
                s.list_push("idx", &format!("t{i}"), false, None)
                    .await
                    .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(storage.list_len("idx").await.unwrap(), 50);
    }

    #[tokio::test]
    async fn test_scan_pagination_complete() {
        let storage = MemoryStorage::new();
        for i in 0..1000 {
            storage
                .set(&format!("sa:token:{i:04}"), "v", None)
                .await
                .unwrap();
        }
        let mut cursor = 0u64;
        let mut all = Vec::new();
        loop {
            let page = storage.scan("sa:token:*", cursor, 100).await.unwrap();
            all.extend(page.keys);
            if page.next_cursor == 0 {
                break;
            }
            cursor = page.next_cursor;
        }
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 1000);
    }

    #[tokio::test]
    async fn test_list_push_len_and_scan_anchor() {
        let storage = MemoryStorage::new();
        for i in 0..50 {
            storage
                .list_push("idx", &format!("t{i}"), false, None)
                .await
                .unwrap();
        }
        assert_eq!(storage.list_len("idx").await.unwrap(), 50);
        storage.set("x-sa:token:y", "bad", None).await.unwrap();
        storage.set("sa:token:a", "ok", None).await.unwrap();
        let page = storage.scan("sa:token:*", 0, 100).await.unwrap();
        assert_eq!(page.keys, vec!["sa:token:a".to_string()]);
    }

    #[tokio::test]
    async fn test_counting_storage_decorator() {
        let inner = Arc::new(MemoryStorage::new()) as Arc<dyn SaStorage>;
        let counting = CountingStorage::new(Arc::clone(&inner));

        counting.set("k", "v", None).await.unwrap();
        assert_eq!(counting.get("k").await.unwrap(), Some("v".into()));
        assert_eq!(counting.get_count(), 1);
        assert_eq!(counting.set_count(), 1);

        counting.reset_counts();
        counting.get("k").await.unwrap();
        counting.delete("k").await.unwrap();
        assert_eq!(counting.get_count(), 1);
        assert_eq!(counting.delete_count(), 1);
        assert_eq!(counting.set_count(), 0);
    }
}
