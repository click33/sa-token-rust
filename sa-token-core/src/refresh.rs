// Author: 金书记 | Author: Jin Shuji
//! Refresh Token Module | Refresh Token 模块
//!
//! Implements token refresh mechanism for long-term authentication
//! 实现长期认证的 Token 刷新机制

use crate::config::SaTokenConfig;
use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use crate::keys::LOGIN_TYPE_DEFAULT;
use crate::repository::TokenRepo;
use crate::token::{TokenGenerator, TokenInfo, TokenValue};
use chrono::{DateTime, Duration, Utc};
use sa_token_adapter::storage::SaStorage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Refresh token storage record (A2-5) | Refresh token 存储记录
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshTokenRecord {
    access_token: String,
    login_id: String,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expire_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refreshed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extra_data: Option<serde_json::Value>,
}

impl RefreshTokenRecord {
    fn new(access_token: impl Into<String>, login_id: impl Into<String>) -> Self {
        Self {
            access_token: access_token.into(),
            login_id: login_id.into(),
            created_at: Utc::now().to_rfc3339(),
            expire_time: None,
            refreshed_at: None,
            extra_data: None,
        }
    }

    fn with_expire_time(mut self, expire: Option<DateTime<Utc>>) -> Self {
        self.expire_time = expire.map(|t| t.to_rfc3339());
        self
    }

    fn with_extra_data(mut self, extra: serde_json::Value) -> Self {
        self.extra_data = Some(extra);
        self
    }

    fn mark_refreshed(&mut self, new_access_token: impl Into<String>) {
        self.access_token = new_access_token.into();
        self.refreshed_at = Some(Utc::now().to_rfc3339());
    }
}

fn chrono_from_std(d: std::time::Duration) -> SaTokenResult<Duration> {
    Duration::from_std(d)
        .map_err(|_| SaTokenError::ConfigError("token timeout duration out of range".into()))
}

/// Refresh Token Manager | Refresh Token 管理器
#[derive(Clone)]
pub struct RefreshTokenManager {
    dao: Arc<SaTokenDao>,
    /// Token 仓储：刷新时同步映射与多设备索引，禁止只改标量旁路。
    /// Token repo: refresh must update mappings and the multi-device index together.
    token_repo: Arc<TokenRepo>,
    config: Arc<SaTokenConfig>,
}

impl std::fmt::Debug for RefreshTokenManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshTokenManager { .. }")
    }
}

impl RefreshTokenManager {
    /// Create with shared Dao + TokenRepo | 用共享 Dao 与 TokenRepo 创建
    pub fn new(
        dao: Arc<SaTokenDao>,
        token_repo: Arc<TokenRepo>,
        config: Arc<SaTokenConfig>,
    ) -> Self {
        Self {
            dao,
            token_repo,
            config,
        }
    }

    /// Create from Dao（自建 TokenRepo，兼容旧调用）
    /// Create from Dao (builds a TokenRepo; keeps old call sites working)
    pub fn from_dao(dao: Arc<SaTokenDao>) -> Self {
        let config = dao.config().clone();
        let token_repo = Arc::new(TokenRepo::new(dao.clone(), config.clone()));
        Self {
            dao,
            token_repo,
            config,
        }
    }

    /// Create from raw storage（example / 测试）| Create from raw storage
    pub fn from_storage(storage: Arc<dyn SaStorage>, config: Arc<SaTokenConfig>) -> Self {
        let dao = Arc::new(SaTokenDao::new(storage, config.clone()));
        let token_repo = Arc::new(TokenRepo::new(dao.clone(), config.clone()));
        Self {
            dao,
            token_repo,
            config,
        }
    }

    fn refresh_key(&self, refresh_token: &str) -> String {
        self.dao.keys().refresh(refresh_token)
    }

    fn user_index_key(&self, login_type: &str, login_id: &str) -> String {
        self.dao.keys().refresh_user_index(login_type, login_id)
    }

    /// Generate a new refresh token | 生成新的 refresh token
    pub fn generate(&self, login_id: &str) -> String {
        format!(
            "refresh_{}_{}_{}",
            Utc::now().timestamp_millis(),
            login_id,
            Uuid::new_v4().simple()
        )
    }

    /// Store refresh token with associated access token | 存储 refresh token 及其关联的访问令牌
    pub async fn store(
        &self,
        refresh_token: &str,
        access_token: &str,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<()> {
        self.store_with_extra(refresh_token, access_token, login_type, login_id, None)
            .await
    }

    /// `store_with_extra` — store with extra | `store_with_extra`
    pub async fn store_with_extra(
        &self,
        refresh_token: &str,
        access_token: &str,
        login_type: &str,
        login_id: &str,
        extra_data: Option<&serde_json::Value>,
    ) -> SaTokenResult<()> {
        let key = self.refresh_key(refresh_token);
        let expire_time = if self.config.refresh_token_timeout > 0 {
            Some(Utc::now() + Duration::seconds(self.config.refresh_token_timeout))
        } else {
            None
        };

        let mut record =
            RefreshTokenRecord::new(access_token, login_id).with_expire_time(expire_time);
        if let Some(extra) = extra_data {
            record = record.with_extra_data(extra.clone());
        }

        let ttl = if self.config.refresh_token_timeout > 0 {
            Some(std::time::Duration::from_secs(
                self.config.refresh_token_timeout as u64,
            ))
        } else {
            None
        };

        self.dao.set_object(&key, &record, ttl).await?;
        self.dao
            .list_push_unique(
                &self.user_index_key(login_type, login_id),
                refresh_token,
                None,
            )
            .await?;
        Ok(())
    }

    /// Validate refresh token | 验证 refresh token
    pub async fn validate(&self, refresh_token: &str) -> SaTokenResult<String> {
        let key = self.refresh_key(refresh_token);
        let record: RefreshTokenRecord = self
            .dao
            .get_object(&key)
            .await?
            .ok_or(SaTokenError::RefreshTokenNotFound)?;

        let login_id = record.login_id.clone();
        if login_id.is_empty() {
            return Err(SaTokenError::RefreshTokenMissingLoginId);
        }

        if let Some(expire_str) = record.expire_time.as_deref() {
            let expire_time = DateTime::parse_from_rfc3339(expire_str)
                .map_err(|_| SaTokenError::RefreshTokenInvalidExpireTime)?
                .with_timezone(&Utc);

            if Utc::now() > expire_time {
                self.delete(refresh_token).await?;
                return Err(SaTokenError::TokenExpired);
            }
        }

        Ok(login_id)
    }

    /// Refresh access token using refresh token | 使用 refresh token 刷新访问令牌
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> SaTokenResult<(TokenValue, String)> {
        let login_id = self.validate(refresh_token).await?;

        let key = self.refresh_key(refresh_token);
        let mut record: RefreshTokenRecord = self
            .dao
            .get_object(&key)
            .await?
            .ok_or(SaTokenError::RefreshTokenNotFound)?;

        let extra_data = record.extra_data.clone();
        let new_access_token = match &extra_data {
            Some(extra) => {
                TokenGenerator::generate_with_login_id_and_extra(&self.config, &login_id, extra)?
            }
            None => TokenGenerator::generate_with_login_id(&self.config, &login_id)?,
        };

        let mut token_info = TokenInfo::new(new_access_token.clone(), login_id.as_str());
        token_info.update_active_time();
        token_info.refresh_token = Some(refresh_token.to_string());
        if self.config.refresh_token_timeout > 0 {
            token_info.refresh_token_expire_time =
                Some(Utc::now() + Duration::seconds(self.config.refresh_token_timeout));
        }
        if let Some(extra) = &extra_data {
            token_info.extra_data = Some(extra.clone());
        }
        if token_info.expire_time.is_none()
            && let Some(timeout) = self.config.timeout_duration()
        {
            token_info.expire_time = Some(Utc::now() + chrono_from_std(timeout)?);
        }

        // 刷新必须同步：token 体、反向映射、login:token 标量、多设备索引；并删掉旧 access。
        // Refresh must update body, reverse map, login:token scalar, index; then drop the old access.
        let login_type = LOGIN_TYPE_DEFAULT;
        let old_access = record.access_token.as_str();

        self.token_repo.save_token_info(&token_info).await?;
        self.token_repo
            .save_token_id_mapping(new_access_token.as_str(), login_type, &login_id)
            .await?;
        self.token_repo
            .save_login_mapping(login_type, &login_id, new_access_token.as_str())
            .await?;
        self.token_repo
            .replace_index(login_type, &login_id, old_access, new_access_token.as_str())
            .await?;
        self.token_repo.delete_token_info(old_access).await?;
        self.token_repo.delete_token_id_mapping(old_access).await?;

        record.mark_refreshed(new_access_token.as_str());

        let ttl = if self.config.refresh_token_timeout > 0 {
            Some(std::time::Duration::from_secs(
                self.config.refresh_token_timeout as u64,
            ))
        } else {
            None
        };

        self.dao.set_object(&key, &record, ttl).await?;

        Ok((new_access_token, login_id))
    }

    /// Delete refresh token | 删除 refresh token
    pub async fn delete(&self, refresh_token: &str) -> SaTokenResult<()> {
        let key = self.refresh_key(refresh_token);

        if let Ok(Some(record)) = self.dao.get_object::<RefreshTokenRecord>(&key).await {
            let _ = self
                .dao
                .list_remove(
                    &self.user_index_key(LOGIN_TYPE_DEFAULT, &record.login_id),
                    refresh_token,
                )
                .await;
        }

        self.dao.delete(&key).await?;
        Ok(())
    }

    /// Get all refresh tokens for a user | 获取用户的所有 refresh token
    pub async fn get_user_refresh_tokens(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<String>> {
        self.dao
            .list_range(&self.user_index_key(login_type, login_id), 0, None)
            .await
    }

    /// `revoke_all_for_user` — revoke all for user | `revoke_all_for_user`
    pub async fn revoke_all_for_user(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        let tokens = self.get_user_refresh_tokens(login_type, login_id).await?;
        for token in tokens {
            self.delete(&token).await?;
        }
        let idx = self.user_index_key(login_type, login_id);
        let _ = self.dao.delete(&idx).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TokenStyle;
    use sa_token_storage_memory::MemoryStorage;

    fn create_test_config() -> Arc<SaTokenConfig> {
        Arc::new(SaTokenConfig {
            token_style: TokenStyle::Uuid,
            timeout: 3600,
            refresh_token_timeout: 7200,
            enable_refresh_token: true,
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn test_refresh_token_generation() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::from_storage(storage, config);

        let token1 = refresh_mgr.generate("user_123");
        let token2 = refresh_mgr.generate("user_123");

        assert_ne!(token1, token2);
        assert!(token1.starts_with("refresh_"));
    }

    #[tokio::test]
    async fn test_refresh_token_store_and_validate() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::from_storage(storage, config);

        let refresh_token = refresh_mgr.generate("user_123");
        let access_token = "access_token_123";

        refresh_mgr
            .store(&refresh_token, access_token, LOGIN_TYPE_DEFAULT, "user_123")
            .await
            .unwrap();

        let login_id = refresh_mgr.validate(&refresh_token).await.unwrap();
        assert_eq!(login_id, "user_123");

        let tokens = refresh_mgr
            .get_user_refresh_tokens(LOGIN_TYPE_DEFAULT, "user_123")
            .await
            .unwrap();
        assert_eq!(tokens, vec![refresh_token]);
    }

    #[tokio::test]
    async fn test_refresh_access_token() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::from_storage(storage.clone(), config.clone());

        let refresh_token = refresh_mgr.generate("user_123");
        let old_access_token = "old_access_token";

        refresh_mgr
            .store(
                &refresh_token,
                old_access_token,
                LOGIN_TYPE_DEFAULT,
                "user_123",
            )
            .await
            .unwrap();

        let (new_access_token, login_id) = refresh_mgr
            .refresh_access_token(&refresh_token)
            .await
            .unwrap();

        assert_eq!(login_id, "user_123");
        assert_ne!(new_access_token.as_str(), old_access_token);

        let token_key =
            crate::keys::SaKeys::from_config(&config).token_info(new_access_token.as_str());
        let stored = storage.get(&token_key).await.unwrap();
        assert!(stored.is_some());

        // 刷新后旧 access 的 token_info 必须删除
        let old_key = crate::keys::SaKeys::from_config(&config).token_info(old_access_token);
        let old_stored = storage.get(&old_key).await.unwrap();
        assert!(
            old_stored.is_none(),
            "old access token_info must be removed after refresh"
        );
    }

    #[tokio::test]
    async fn test_delete_refresh_token() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::from_storage(storage, config);

        let refresh_token = refresh_mgr.generate("user_123");
        refresh_mgr
            .store(&refresh_token, "access", LOGIN_TYPE_DEFAULT, "user_123")
            .await
            .unwrap();

        refresh_mgr.delete(&refresh_token).await.unwrap();

        let result = refresh_mgr.validate(&refresh_token).await;
        assert!(result.is_err());

        let tokens = refresh_mgr
            .get_user_refresh_tokens(LOGIN_TYPE_DEFAULT, "user_123")
            .await
            .unwrap();
        assert!(tokens.is_empty());
    }

    #[tokio::test]
    async fn test_revoke_all_for_user() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::from_storage(storage, config);

        let rt1 = refresh_mgr.generate("user_123");
        let rt2 = refresh_mgr.generate("user_123");
        refresh_mgr
            .store(&rt1, "a1", LOGIN_TYPE_DEFAULT, "user_123")
            .await
            .unwrap();
        refresh_mgr
            .store(&rt2, "a2", LOGIN_TYPE_DEFAULT, "user_123")
            .await
            .unwrap();

        refresh_mgr
            .revoke_all_for_user(LOGIN_TYPE_DEFAULT, "user_123")
            .await
            .unwrap();

        assert!(refresh_mgr.validate(&rt1).await.is_err());
        assert!(refresh_mgr.validate(&rt2).await.is_err());
        assert!(
            refresh_mgr
                .get_user_refresh_tokens(LOGIN_TYPE_DEFAULT, "user_123")
                .await
                .unwrap()
                .is_empty()
        );
    }
}
