// Author: 金书记
//
//! # sa-token-storage-database
//!
//! 基于 sqlx 的关系型数据库存储实现（默认 PostgreSQL，可选 MySQL）。
//!
//! ## DDL
//!
//! 见 [`migrations/001_sa_token_storage.sql`](../../migrations/001_sa_token_storage.sql)。

// postgres 与 mysql 后端互斥，避免 sqlx 同时编译两套驱动
#[cfg(all(feature = "postgres", feature = "mysql"))]
compile_error!(
    "Features `postgres` and `mysql` are mutually exclusive; enable only one database backend"
);

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sa_token_adapter::storage::{SaStorage, ScanPage, StorageError, StorageResult};
use sqlx::{Pool, Postgres};

/// PostgreSQL 存储实现
#[derive(Clone)]
pub struct DatabaseStorage {
    pool: Pool<Postgres>,
}

impl std::fmt::Debug for DatabaseStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DatabaseStorage { .. }")
    }
}

impl DatabaseStorage {
    /// 连接数据库并确保表结构存在
    pub async fn new(database_url: &str) -> StorageResult<Self> {
        let pool = Pool::<Postgres>::connect(database_url)
            .await
            .map_err(|e| StorageError::ConnectionError(e.to_string()))?;

        let storage = Self { pool };
        storage.migrate().await?;
        Ok(storage)
    }

    /// 使用已有连接池
    pub fn from_pool(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    /// 执行内嵌 DDL（幂等）
    pub async fn migrate(&self) -> StorageResult<()> {
        let ddl = include_str!("../migrations/001_sa_token_storage.sql");
        for statement in ddl.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            sqlx::query(statement)
                .execute(&self.pool)
                .await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        }
        Ok(())
    }

    async fn delete_expired(&self, key: &str) -> StorageResult<()> {
        sqlx::query("DELETE FROM sa_token_storage WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        Ok(())
    }

    fn is_expired(expire_at: Option<DateTime<Utc>>) -> bool {
        expire_at.is_some_and(|t| Utc::now() > t)
    }
}

/// 将 `*` 通配符转为 SQL LIKE 模式，并转义 `%` / `_`
pub fn pattern_to_like(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    for ch in pattern.chars() {
        match ch {
            '*' => out.push('%'),
            '%' | '_' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

#[async_trait]
impl SaStorage for DatabaseStorage {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        let row: Option<(String, Option<DateTime<Utc>>)> =
            sqlx::query_as("SELECT value, expire_at FROM sa_token_storage WHERE key = $1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        match row {
            Some((_value, expire_at)) if Self::is_expired(expire_at) => {
                self.delete_expired(key).await?;
                Ok(None)
            }
            Some((value, _)) => Ok(Some(value)),
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()> {
        let expire_at: Option<DateTime<Utc>> = ttl
            .and_then(|d| chrono::Duration::from_std(d).ok())
            .map(|d| Utc::now() + d);

        sqlx::query(
            r#"
            INSERT INTO sa_token_storage (key, value, expire_at, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (key) DO UPDATE
            SET value = EXCLUDED.value,
                expire_at = EXCLUDED.expire_at,
                updated_at = NOW()
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(expire_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        Ok(())
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        sqlx::query("DELETE FROM sa_token_storage WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        Ok(self.get(key).await?.is_some())
    }

    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()> {
        let Some(delta) = chrono::Duration::from_std(ttl).ok() else {
            return Ok(());
        };
        let expire_at = Utc::now() + delta;
        let updated = sqlx::query(
            "UPDATE sa_token_storage SET expire_at = $1, updated_at = NOW() WHERE key = $2",
        )
        .bind(expire_at)
        .bind(key)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::OperationFailed(e.to_string()))?
        .rows_affected();

        if updated == 0 {
            return Err(StorageError::KeyNotFound(key.to_string()));
        }
        Ok(())
    }

    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>> {
        let row: Option<Option<DateTime<Utc>>> =
            sqlx::query_scalar("SELECT expire_at FROM sa_token_storage WHERE key = $1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        match row {
            None => Ok(None),
            Some(None) => Ok(None),
            Some(Some(expire_at)) if Self::is_expired(Some(expire_at)) => {
                self.delete_expired(key).await?;
                Ok(None)
            }
            Some(Some(expire_at)) => {
                let remaining = expire_at.signed_duration_since(Utc::now());
                if remaining.num_milliseconds() <= 0 {
                    Ok(Some(Duration::ZERO))
                } else {
                    Ok(Some(remaining.to_std().unwrap_or(Duration::ZERO)))
                }
            }
        }
    }

    async fn clear(&self) -> StorageResult<()> {
        sqlx::query("TRUNCATE TABLE sa_token_storage")
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        Ok(())
    }

    async fn set_if_absent(
        &self,
        _key: &str,
        _value: &str,
        _ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        Err(StorageError::Unsupported("set_if_absent"))
    }

    async fn get_del(&self, _key: &str) -> StorageResult<Option<String>> {
        Err(StorageError::Unsupported("get_del"))
    }

    async fn compare_and_swap(
        &self,
        _key: &str,
        _expected: Option<&str>,
        _new_value: &str,
        _ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        Err(StorageError::Unsupported("compare_and_swap"))
    }

    async fn compare_and_delete(&self, _key: &str, _expected: &str) -> StorageResult<bool> {
        Err(StorageError::Unsupported("compare_and_delete"))
    }

    async fn list_push(
        &self,
        _key: &str,
        _member: &str,
        _unique: bool,
        _ttl: Option<Duration>,
    ) -> StorageResult<usize> {
        Err(StorageError::Unsupported("list_push"))
    }

    async fn list_remove(&self, _key: &str, _member: &str) -> StorageResult<bool> {
        Err(StorageError::Unsupported("list_remove"))
    }

    async fn list_range(
        &self,
        _key: &str,
        _start: usize,
        _limit: Option<usize>,
    ) -> StorageResult<Vec<String>> {
        Err(StorageError::Unsupported("list_range"))
    }

    async fn list_len(&self, _key: &str) -> StorageResult<usize> {
        Err(StorageError::Unsupported("list_len"))
    }

    async fn scan(&self, _pattern: &str, _cursor: u64, _limit: usize) -> StorageResult<ScanPage> {
        Err(StorageError::Unsupported("scan"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_pattern_escapes_wildcards() {
        assert_eq!(pattern_to_like("sa:token:*"), "sa:token:%");
        assert_eq!(pattern_to_like("a%b_c"), "a\\%b\\_c");
    }
}

#[cfg(all(test, feature = "postgres"))]
mod postgres_tests {
    use super::*;

    fn database_url() -> Option<String> {
        std::env::var("DATABASE_URL").ok()
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL (set DATABASE_URL)"]
    async fn database_storage_roundtrip() {
        let Some(url) = database_url() else {
            return;
        };
        let storage = DatabaseStorage::new(&url).await.expect("connect");
        storage
            .set("sa:test:1", "v1", Some(Duration::from_secs(60)))
            .await
            .unwrap();
        assert_eq!(storage.get("sa:test:1").await.unwrap(), Some("v1".into()));
        assert!(storage.exists("sa:test:1").await.unwrap());
        let ttl = storage.ttl("sa:test:1").await.unwrap();
        assert!(ttl.is_some());
        storage.delete("sa:test:1").await.unwrap();
        assert!(!storage.exists("sa:test:1").await.unwrap());

        let err = storage.scan("sa:test:*", 0, 100).await.unwrap_err();
        assert!(matches!(err, StorageError::Unsupported(_)));
    }
}
