// Author: 金书记
//
//! Token-Session 双轨（独立于 Account-Session）。
//!
//! Token-Session 与 Account-Session 是两条独立的数据轨：
//! - Account-Session 按账号聚合，同账号多设备共享同一份
//! - Token-Session 按 token 隔离，每次登录各有一份，token 下线即销毁

use crate::error::{SaTokenError, SaTokenResult};
use crate::manager::SaTokenManager;
use crate::session::SaSession;
use crate::token::TokenValue;

impl SaTokenManager {
    /// Token-Session 的 id 命名规则（逻辑 id，非存储键）
    fn token_session_id(token: &str) -> String {
        format!("token-session:{token}")
    }

    /// 获取 Token-Session（不存在时按配置决定是否落盘创建）
    pub async fn get_token_session(&self, token: &TokenValue) -> SaTokenResult<SaSession> {
        if self.config.token_session_check_login && !self.is_valid(token).await {
            return Err(SaTokenError::NotLogin);
        }

        if let Some(session) = self.session_repo().get_token_session(token).await? {
            return Ok(session);
        }

        let session = SaSession::new(Self::token_session_id(token.as_str()));
        if self.config.right_now_create_token_session {
            self.session_repo()
                .save_token_session(token, &session)
                .await?;
        }
        Ok(session)
    }

    /// 匿名 Token-Session：跳过登录校验，且从不自动落盘
    pub async fn get_anon_token_session(&self, token: &TokenValue) -> SaTokenResult<SaSession> {
        if let Some(session) = self.session_repo().get_token_session(token).await? {
            return Ok(session);
        }
        Ok(SaSession::new(Self::token_session_id(token.as_str())))
    }

    /// 保存 Token-Session（TTL 与 token 生命周期对齐）
    pub async fn save_token_session(
        &self,
        token: &TokenValue,
        session: &SaSession,
    ) -> SaTokenResult<()> {
        self.session_repo().save_token_session(token, session).await
    }

    /// 删除 Token-Session
    pub async fn delete_token_session(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.session_repo().delete_token_session(token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SaTokenConfig;
    use sa_token_storage_memory::MemoryStorage;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_token_session_create_and_delete() {
        let config = SaTokenConfig {
            right_now_create_token_session: true,
            ..Default::default()
        };
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), config);
        let token = mgr.login("u1").await.unwrap();
        let mut session = mgr.get_token_session(&token).await.unwrap();
        assert!(session.id.starts_with("token-session:"));
        session.set("k", "v").unwrap();
        mgr.save_token_session(&token, &session).await.unwrap();
        let loaded = mgr.get_token_session(&token).await.unwrap();
        assert_eq!(loaded.get::<String>("k"), Some("v".to_string()));
        mgr.delete_token_session(&token).await.unwrap();
        // 灰盒：存储键必须消失（不能只靠 get 重建后看空字段）
        let key = mgr.keys().token_session(token.as_str());
        let raw = mgr.storage().get(&key).await.unwrap();
        assert!(raw.is_none(), "token_session key must be deleted");
        let after = mgr.get_token_session(&token).await.unwrap();
        assert!(after.get::<String>("k").is_none());
    }
}
