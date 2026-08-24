// Author: 金书记
//
//! Nonce Manager | Nonce 管理器
//!
//! Prevents replay attacks by tracking used nonces
//! 通过跟踪已使用的 nonce 来防止重放攻击
//!
//! ## Overview | 概述
//!
//! A **nonce** (number used once) is a unique value that can only be used one time,
//! preventing replay attacks where an attacker reuses a valid request.
//! **nonce**（一次性数字）是一个只能使用一次的唯一值，防止攻击者重用有效请求的重放攻击。
//!
//! ## Integration with Sa-Token | 与 Sa-Token 的集成
//!
//! Nonce is used in several Sa-Token scenarios:
//! Nonce 在 Sa-Token 的多个场景中使用：
//!
//! 1. **Login with Nonce** | 带 Nonce 的登录
//!    - Prevents replay of login requests
//!    - 防止登录请求的重放
//!
//! 2. **Token Creation** | Token 创建
//!    - Each token can have an associated nonce
//!    - 每个 token 可以关联一个 nonce
//!
//! 3. **OAuth2 / SSO** | OAuth2 / SSO
//!    - Used in authorization codes and state parameters
//!    - 用于授权码和状态参数
//!
//! 4. **Sensitive Operations** | 敏感操作
//!    - Password changes, account deletion, etc.
//!    - 密码修改、账户删除等
//!
//! ## Workflow | 工作流程
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Nonce Lifecycle                          │
//! │                    Nonce 生命周期                            │
//! └─────────────────────────────────────────────────────────────┘
//!
//! Client                     NonceManager              Storage
//! 客户端                     Nonce管理器               存储
//!   │                             │                        │
//!   │  1. Request nonce           │                        │
//!   │  请求 nonce                 │                        │
//!   │────────────────────────────▶│                        │
//!   │                             │                        │
//!   │  2. generate()              │                        │
//!   │                             │  生成唯一 nonce        │
//!   │                             │  nonce_TIMESTAMP_UUID  │
//!   │                             │                        │
//!   │  3. Return nonce            │                        │
//!   │  返回 nonce                 │                        │
//!   │◀────────────────────────────│                        │
//!   │                             │                        │
//!   │  4. Use nonce in request    │                        │
//!   │  在请求中使用 nonce         │                        │
//!   │────────────────────────────▶│                        │
//!   │                             │                        │
//!   │  5. validate_and_consume()  │                        │
//!   │                             │  Check not used        │
//!   │                             │  检查未使用             │
//!   │                             │─────────────────────▶  │
//!   │                             │  Get nonce key         │
//!   │                             │                        │
//!   │                             │  Not found = valid     │
//!   │                             │  未找到 = 有效          │
//!   │                             │◀─────────────────────  │
//!   │                             │                        │
//!   │                             │  Store nonce (TTL)     │
//!   │                             │  存储 nonce            │
//!   │                             │─────────────────────▶  │
//!   │                             │                        │
//!   │  6. Request processed       │                        │
//!   │  请求已处理                 │                        │
//!   │◀────────────────────────────│                        │
//!   │                             │                        │
//!   │  7. Reuse same nonce (ATTACK)                        │
//!   │  重用相同 nonce（攻击）     │                        │
//!   │────────────────────────────▶│                        │
//!   │                             │  Check if used         │
//!   │                             │  检查是否已使用         │
//!   │                             │─────────────────────▶  │
//!   │                             │  Found = already used  │
//!   │                             │  找到 = 已使用          │
//!   │                             │◀─────────────────────  │
//!   │                             │                        │
//!   │  ❌ Reject (NonceAlreadyUsed)                        │
//!   │  拒绝（Nonce已使用）         │                        │
//!   │◀────────────────────────────│                        │
//!   │                             │                        │
//!   │                          [After TTL expires]         │
//!   │                          [TTL 过期后]                 │
//!   │                             │   Auto cleanup         │
//!   │                             │   自动清理              │
//!   │                             │         X──────────────│
//! ```
//!
//! ## Storage Keys | 存储键格式
//!
//! ```text
//! sa:nonce:{nonce_value}
//!   - Stores: { "login_id": "...", "created_at": "..." }
//!   - TTL: Configured timeout (default: 60 seconds)
//!   - Purpose: Mark nonce as used
//!   
//!   存储：{ "login_id": "...", "created_at": "..." }
//!   TTL：配置的超时时间（默认：60秒）
//!   目的：标记 nonce 为已使用
//! ```
//!
//! ## Security Considerations | 安全考虑
//!
//! ```text
//! 1. ✅ One-Time Use | 一次性使用
//!    - Nonce can only be used once
//!    - Stored after first use to prevent reuse
//!    
//! 2. ✅ Time-Limited | 时间限制
//!    - Nonces expire after timeout (default: 60s)
//!    - Prevents storage bloat
//!    
//! 3. ✅ Unique Generation | 唯一生成
//!    - UUID + timestamp ensures uniqueness
//!    - Collision probability: negligible
//!    
//! 4. ✅ Timestamp Validation | 时间戳验证
//!    - check_timestamp() validates time window
//!    - Prevents time-based attacks
//!    
//! 5. ✅ Atomic Operations | 原子操作
//!    - validate_and_consume() is atomic
//!    - Prevents race conditions
//! ```
//!
//! ## Usage Examples | 使用示例
//!
//! ### Example 1: Login with Nonce | 带 Nonce 的登录
//!
//! ```rust,ignore
//! use sa_token_core::manager::SaTokenManager;
//!
//! // Client requests nonce
//! let nonce = nonce_manager.generate();
//! // Returns: "nonce_1234567890123_abc123def456"
//!
//! // Client sends login request with nonce
//! let token = manager.login_with_options(
//!     "user_123",
//!     None,
//!     None,
//!     None,
//!     Some(nonce.clone()),  // ← Nonce here
//!     None,
//! ).await?;
//!
//! // Server validates and consumes nonce (inside login_with_token_info)
//! nonce_manager.validate_and_consume(&nonce, "user_123").await?;
//! // ✅ First use: OK
//! // ❌ Second use: NonceAlreadyUsed error
//! ```
//!
//! ### Example 2: Sensitive Operation with Nonce | 带 Nonce 的敏感操作
//!
//! ```rust,ignore
//! // Change password with nonce protection
//! async fn change_password(
//!     user_id: &str,
//!     new_password: &str,
//!     nonce: &str,
//! ) -> Result<()> {
//!     // Validate nonce
//!     nonce_manager.validate_and_consume(nonce, user_id).await?;
//!     
//!     // Proceed with password change
//!     update_password(user_id, new_password).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Best Practices | 最佳实践
//!
//! 1. **Always generate nonces server-side** | 始终在服务端生成 nonce
//!    - Don't let clients generate their own nonces
//!    - 不要让客户端生成自己的 nonce
//!
//! 2. **Use appropriate timeout** | 使用适当的超时时间
//!    - Short timeout (30-60s) for most operations
//!    - Longer timeout (5-10min) for complex flows
//!    - 大多数操作使用短超时（30-60秒）
//!    - 复杂流程使用较长超时（5-10分钟）
//!
//! 3. **Validate timestamp** | 验证时间戳
//!    - Use check_timestamp() for additional validation
//!    - 使用 check_timestamp() 进行额外验证
//!
//! 4. **One nonce per operation** | 每个操作一个 nonce
//!    - Don't reuse nonces across different operations
//!    - 不要在不同操作间重用 nonce
//!
//! 5. **Combine with other security measures** | 与其他安全措施结合
//!    - Use nonces WITH authentication, not instead of it
//!    - 将 nonce 与认证结合使用，而不是替代认证
//! ```

use crate::config::SaTokenConfig;
use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use chrono::{DateTime, Utc};
use sa_token_adapter::storage::SaStorage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Nonce storage record (A2-1) | Nonce 存储记录
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NonceRecord {
    /// Associated login id | 关联登录 ID
    pub login_id: String,
    /// Creation time (RFC 3339) | 创建时间（RFC 3339）
    pub created_at: String,
}

impl NonceRecord {
    /// Build a new record for `login_id` | 为 login_id 新建记录
    pub fn new(login_id: impl Into<String>) -> Self {
        Self {
            login_id: login_id.into(),
            created_at: Utc::now().to_rfc3339(),
        }
    }
}

/// Nonce Manager | Nonce 管理器
#[derive(Clone)]
pub struct NonceManager {
    dao: Arc<SaTokenDao>,
    timeout: i64,
}

impl std::fmt::Debug for NonceManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NonceManager { .. }")
    }
}

impl NonceManager {
    /// Create from Dao | 从 Dao 创建
    pub fn from_dao(dao: Arc<SaTokenDao>, timeout: i64) -> Self {
        Self { dao, timeout }
    }

    /// Legacy wrapper: builds a Dao with default config + given timeout.
    /// 遗留包装：用默认配置构造 Dao。
    pub fn new(storage: Arc<dyn SaStorage>, timeout: i64) -> Self {
        let cfg = SaTokenConfig {
            nonce_timeout: timeout,
            ..SaTokenConfig::default()
        };
        Self::from_dao(Arc::new(SaTokenDao::new(storage, Arc::new(cfg))), timeout)
    }

    fn ttl(&self) -> Option<std::time::Duration> {
        if self.timeout > 0 {
            Some(std::time::Duration::from_secs(self.timeout as u64))
        } else {
            None
        }
    }

    /// Generate a new nonce | 生成新的 nonce
    pub fn generate(&self) -> String {
        format!(
            "nonce_{}_{}",
            Utc::now().timestamp_millis(),
            Uuid::new_v4().simple()
        )
    }

    /// Store and mark nonce as used | 存储并标记 nonce 为已使用
    pub async fn store(&self, nonce: &str, login_id: &str) -> SaTokenResult<()> {
        let key = self.dao.keys().nonce(nonce);
        let record = NonceRecord::new(login_id);
        self.dao.set_object(&key, &record, self.ttl()).await
    }

    /// Retrieve nonce record for audit (optional) | 检索 nonce 记录（审计可选）
    pub async fn get_record(&self, nonce: &str) -> SaTokenResult<Option<NonceRecord>> {
        let key = self.dao.keys().nonce(nonce);
        self.dao.get_object(&key).await
    }

    /// Validate nonce and ensure it hasn't been used | 验证 nonce 并确保未被使用
    pub async fn validate(&self, nonce: &str) -> SaTokenResult<bool> {
        let key = self.dao.keys().nonce(nonce);
        Ok(self.dao.get_string(&key).await?.is_none())
    }

    /// Validate and consume nonce atomically via set_if_absent.
    /// 通过 set_if_absent 原子校验并消费 nonce。
    pub async fn validate_and_consume(&self, nonce: &str, login_id: &str) -> SaTokenResult<()> {
        if nonce.trim().is_empty() {
            return Err(SaTokenError::InvalidToken("nonce must not be empty".into()));
        }
        let key = self.dao.keys().nonce(nonce);
        let record = NonceRecord::new(login_id);
        let raw = self.dao.encode(&record)?;
        let occupied = self.dao.set_if_absent(&key, &raw, self.ttl()).await?;
        if !occupied {
            return Err(SaTokenError::NonceAlreadyUsed);
        }
        Ok(())
    }

    /// Extract timestamp from nonce and check if it's within valid time window
    /// 从 nonce 中提取时间戳并检查是否在有效时间窗口内
    pub fn check_timestamp(&self, nonce: &str, window_seconds: i64) -> SaTokenResult<bool> {
        let parts: Vec<&str> = nonce.split('_').collect();
        if parts.len() < 3 {
            return Err(SaTokenError::InvalidNonceFormat);
        }
        let timestamp_ms: i64 = parts
            .get(1)
            .ok_or(SaTokenError::InvalidNonceFormat)?
            .parse()
            .map_err(|_| SaTokenError::InvalidNonceTimestamp)?;
        let now_ms = Utc::now().timestamp_millis();
        let age_seconds = (now_ms - timestamp_ms) / 1000;
        Ok(age_seconds >= 0 && age_seconds <= window_seconds)
    }

    /// Scan and remove expired nonce records | 扫描并删除过期 nonce 记录
    pub async fn cleanup_expired(&self) -> SaTokenResult<usize> {
        if self.timeout <= 0 {
            return Ok(0);
        }
        let pattern = self.dao.keys().scan_pattern("nonce", None);
        let mut removed = 0usize;
        let mut cursor = 0u64;
        let cutoff = Utc::now() - chrono::Duration::seconds(self.timeout);

        loop {
            let page = match self.dao.scan(&pattern, cursor, 200).await {
                Ok(p) => p,
                Err(SaTokenError::StorageError(ref msg)) if msg.contains("Unsupported") => {
                    tracing::warn!("nonce cleanup skipped: scan unsupported on this backend");
                    break;
                }
                Err(e) => return Err(e),
            };

            for key in page.keys {
                if let Some(record) = self.dao.get_object::<NonceRecord>(&key).await? {
                    if let Ok(dt) = DateTime::parse_from_rfc3339(&record.created_at) {
                        if dt.with_timezone(&Utc) < cutoff {
                            self.dao.delete(&key).await?;
                            removed += 1;
                        }
                    }
                }
            }
            if page.next_cursor == 0 {
                break;
            }
            cursor = page.next_cursor;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_storage_memory::MemoryStorage;

    #[tokio::test]
    async fn test_nonce_generation() {
        let storage = Arc::new(MemoryStorage::new());
        let nonce_mgr = NonceManager::new(storage, 60);

        let nonce1 = nonce_mgr.generate();
        let nonce2 = nonce_mgr.generate();

        assert_ne!(nonce1, nonce2);
        assert!(nonce1.starts_with("nonce_"));
    }

    #[tokio::test]
    async fn test_nonce_validation() {
        let storage = Arc::new(MemoryStorage::new());
        let nonce_mgr = NonceManager::new(storage, 60);

        let nonce = nonce_mgr.generate();

        // First validation should succeed
        assert!(nonce_mgr.validate(&nonce).await.unwrap());

        // Store the nonce
        nonce_mgr.store(&nonce, "user_123").await.unwrap();

        // Second validation should fail (already used)
        assert!(!nonce_mgr.validate(&nonce).await.unwrap());
    }

    #[tokio::test]
    async fn test_nonce_validate_and_consume() {
        let storage = Arc::new(MemoryStorage::new());
        let nonce_mgr = NonceManager::new(storage, 60);

        let nonce = nonce_mgr.generate();

        // First use should succeed
        nonce_mgr
            .validate_and_consume(&nonce, "user_123")
            .await
            .unwrap();

        // Second use should fail
        let result = nonce_mgr.validate_and_consume(&nonce, "user_123").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_nonce_timestamp_check() {
        let storage = Arc::new(MemoryStorage::new());
        let nonce_mgr = NonceManager::new(storage, 60);

        let nonce = nonce_mgr.generate();

        // Should be within 60 seconds
        assert!(nonce_mgr.check_timestamp(&nonce, 60).unwrap());

        // Should also be within 1 second
        assert!(nonce_mgr.check_timestamp(&nonce, 1).unwrap());
    }
}
