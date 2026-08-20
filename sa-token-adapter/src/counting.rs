// Author: 金书记
//
//! 测试用装饰器：统计底层存储的 get/set/delete 调用次数
//!
//! 供 P4 断言「auto_renew 窗口内零写入」等性能契约。

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;

use crate::storage::{SaStorage, ScanPage, StorageResult};

/// 包装任意 [`SaStorage`]，统计 get / set / delete 调用次数
pub struct CountingStorage {
    inner: Arc<dyn SaStorage>,
    get_count: AtomicUsize,
    set_count: AtomicUsize,
    delete_count: AtomicUsize,
}

impl std::fmt::Debug for CountingStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CountingStorage { .. }")
    }
}

impl CountingStorage {
    /// Create a new instance | 创建新实例
    pub fn new(inner: Arc<dyn SaStorage>) -> Self {
        Self {
            inner,
            get_count: AtomicUsize::new(0),
            set_count: AtomicUsize::new(0),
            delete_count: AtomicUsize::new(0),
        }
    }

    /// Number of `get` calls observed | 观测到的 `get` 调用次数
    pub fn get_count(&self) -> usize {
        self.get_count.load(Ordering::Relaxed)
    }

    /// Number of `set` calls observed | 观测到的 `set` 调用次数
    pub fn set_count(&self) -> usize {
        self.set_count.load(Ordering::Relaxed)
    }

    /// Number of `delete` calls observed | 观测到的 `delete` 调用次数
    pub fn delete_count(&self) -> usize {
        self.delete_count.load(Ordering::Relaxed)
    }

    /// Reset all call counters | 重置全部调用计数
    pub fn reset_counts(&self) {
        self.get_count.store(0, Ordering::Relaxed);
        self.set_count.store(0, Ordering::Relaxed);
        self.delete_count.store(0, Ordering::Relaxed);
    }

    /// Underlying storage handle | 底层存储句柄
    pub fn inner(&self) -> &Arc<dyn SaStorage> {
        &self.inner
    }
}

#[async_trait]
impl SaStorage for CountingStorage {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        self.get_count.fetch_add(1, Ordering::Relaxed);
        self.inner.get(key).await
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()> {
        self.set_count.fetch_add(1, Ordering::Relaxed);
        self.inner.set(key, value, ttl).await
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        self.delete_count.fetch_add(1, Ordering::Relaxed);
        self.inner.delete(key).await
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        self.inner.exists(key).await
    }

    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()> {
        self.inner.expire(key, ttl).await
    }

    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>> {
        self.inner.ttl(key).await
    }

    async fn clear(&self) -> StorageResult<()> {
        self.inner.clear().await
    }

    // 以下原子/集合/扫描方法透明转发，不计入 write 统计（P4 只关心 get/set/delete）
    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        self.inner.set_if_absent(key, value, ttl).await
    }

    async fn get_del(&self, key: &str) -> StorageResult<Option<String>> {
        self.inner.get_del(key).await
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        self.inner
            .compare_and_swap(key, expected, new_value, ttl)
            .await
    }

    async fn compare_and_delete(&self, key: &str, expected: &str) -> StorageResult<bool> {
        self.inner.compare_and_delete(key, expected).await
    }

    async fn list_push(
        &self,
        key: &str,
        member: &str,
        unique: bool,
        ttl: Option<Duration>,
    ) -> StorageResult<usize> {
        self.inner.list_push(key, member, unique, ttl).await
    }

    async fn list_remove(&self, key: &str, member: &str) -> StorageResult<bool> {
        self.inner.list_remove(key, member).await
    }

    async fn list_range(
        &self,
        key: &str,
        start: usize,
        limit: Option<usize>,
    ) -> StorageResult<Vec<String>> {
        self.inner.list_range(key, start, limit).await
    }

    async fn list_len(&self, key: &str) -> StorageResult<usize> {
        self.inner.list_len(key).await
    }

    async fn scan(&self, pattern: &str, cursor: u64, limit: usize) -> StorageResult<ScanPage> {
        self.inner.scan(pattern, cursor, limit).await
    }
}
