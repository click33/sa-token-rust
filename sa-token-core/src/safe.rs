// Author: 金书记
//
//! Secondary authentication (safe window).
//! 二级认证（安全窗口）。

use std::time::Duration;

use crate::error::{SaTokenError, SaTokenResult};
use crate::manager::SaTokenManager;
use crate::token::TokenValue;

/// Default secondary-auth service id.
/// 默认二级认证业务标识。
pub const DEFAULT_SAFE_SERVICE: &str = "";

/// 二级认证存储标记值
pub const SAFE_AUTH_VALUE: &str = "ok";

impl SaTokenManager {
    fn safe_key(&self, token: &str, service: &str) -> String {
        self.keys().safe(token, service)
    }

    /// 为指定 token 开启二级认证
    pub async fn open_safe(
        &self,
        token: &TokenValue,
        service: &str,
        safe_time: i64,
    ) -> SaTokenResult<()> {
        if safe_time < 0 {
            return Err(SaTokenError::ConfigError(
                "safe_time must be >= 0".to_string(),
            ));
        }

        let ttl = if safe_time == 0 {
            None
        } else {
            Some(Duration::from_secs(safe_time as u64))
        };

        // 走 Dao 漏斗，避免绕过序列化与键契约。
        // Go through Dao so serialization and key contracts are not bypassed.
        self.dao
            .set_string(
                &self.safe_key(token.as_str(), service),
                SAFE_AUTH_VALUE,
                ttl,
            )
            .await?;

        self.event_bus
            .publish(crate::event::SaTokenEvent::open_safe(
                token.as_str(),
                service,
            ))
            .await;

        Ok(())
    }

    /// 判断 token 是否已通过指定业务的二级认证
    pub async fn is_safe(&self, token: &TokenValue, service: &str) -> SaTokenResult<bool> {
        if token.as_str().is_empty() {
            return Ok(false);
        }

        if !self.is_valid(token).await {
            return Ok(false);
        }

        Ok(self
            .dao
            .get_string(&self.safe_key(token.as_str(), service))
            .await?
            .as_deref()
            == Some(SAFE_AUTH_VALUE))
    }

    /// 校验二级认证；未通过抛出 [`SaTokenError::NotSafe`]
    pub async fn check_safe(&self, token: &TokenValue, service: &str) -> SaTokenResult<()> {
        if !self.is_valid(token).await {
            return Err(SaTokenError::NotLogin);
        }

        if !self.is_safe(token, service).await? {
            return Err(SaTokenError::NotSafe(service.to_string()));
        }

        let event = crate::event::SaTokenEvent::safe_verify(token.as_str(), service);
        self.event_bus.publish(event).await;

        Ok(())
    }

    /// 关闭二级认证
    pub async fn close_safe(&self, token: &TokenValue, service: &str) -> SaTokenResult<()> {
        self.dao
            .delete(&self.safe_key(token.as_str(), service))
            .await?;

        self.event_bus
            .publish(crate::event::SaTokenEvent::close_safe(
                token.as_str(),
                service,
            ))
            .await;

        Ok(())
    }

    /// 获取二级认证剩余有效时间（秒）；未认证返回 `None`
    pub async fn get_safe_time(
        &self,
        token: &TokenValue,
        service: &str,
    ) -> SaTokenResult<Option<i64>> {
        match self.dao.ttl(&self.safe_key(token.as_str(), service)).await {
            Ok(Some(d)) => Ok(Some(d.as_secs() as i64)),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SaTokenConfig;
    use sa_token_storage_memory::MemoryStorage;
    use std::sync::Arc;

    fn manager() -> SaTokenManager {
        SaTokenManager::new(Arc::new(MemoryStorage::new()), SaTokenConfig::default())
    }

    #[tokio::test]
    async fn open_check_close_safe() {
        let mgr = manager();
        let token = mgr.login("u1").await.unwrap();
        assert!(!mgr.is_safe(&token, DEFAULT_SAFE_SERVICE).await.unwrap());
        mgr.open_safe(&token, "pay", 120).await.unwrap();
        assert!(mgr.is_safe(&token, "pay").await.unwrap());
        mgr.check_safe(&token, "pay").await.unwrap();
        mgr.close_safe(&token, "pay").await.unwrap();
        assert!(!mgr.is_safe(&token, "pay").await.unwrap());
    }
}
