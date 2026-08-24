// Author: 金书记
//
//! Account / Service Ban | 账号/服务封禁
//!
//! Account disable / ban checks, with one deliberate
//! difference: every method is **account-system aware** (A3-18).

use std::time::Duration;

use crate::error::{SaTokenError, SaTokenResult};
use crate::keys::LOGIN_TYPE_DEFAULT;
use crate::manager::SaTokenManager;

/// Default ban service identifier | 默认封禁服务标识
pub const DEFAULT_DISABLE_SERVICE: &str = "login";

/// Minimum ban level | 最低封禁等级
pub const MIN_DISABLE_LEVEL: i32 = 1;

/// Level returned when an account is not banned | 账号未被封禁时返回的等级
pub const NOT_DISABLE_LEVEL: i32 = -2;

/// Default level written by [`SaTokenManager::disable`] | 默认封禁等级
pub const DEFAULT_DISABLE_LEVEL: i32 = 1;

impl SaTokenManager {
    #[inline]
    fn disable_key_ns(&self, login_type: &str, login_id: &str, service: &str) -> String {
        self.keys().disable(login_type, login_id, service)
    }

    /// Disable at a level for a login type | 按登录类型分级禁用
    pub async fn disable_level_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        service: &str,
        level: i32,
        time: i64,
    ) -> SaTokenResult<()> {
        if login_id.trim().is_empty() {
            return Err(SaTokenError::ConfigError(
                "login_id is required for disable".to_string(),
            ));
        }
        if service.trim().is_empty() {
            return Err(SaTokenError::ConfigError(
                "service is required for disable".to_string(),
            ));
        }
        if level < MIN_DISABLE_LEVEL && level != 0 {
            return Err(SaTokenError::ConfigError(format!(
                "disable level must be >= {MIN_DISABLE_LEVEL} (0 allowed)"
            )));
        }

        let ttl = if time < 0 {
            None
        } else {
            Some(Duration::from_secs(time as u64))
        };

        self.dao
            .set_string(
                &self.disable_key_ns(login_type, login_id, service),
                &level.to_string(),
                ttl,
            )
            .await?;

        let ns = self.account_ns(login_type, login_id);
        let event = crate::event::SaTokenEvent::banned(ns.as_str(), service, level)
            .with_login_type(login_type);
        self.event_bus.publish(event).await;

        Ok(())
    }

    /// Disable for a login type | 按登录类型禁用
    pub async fn disable_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        time: i64,
    ) -> SaTokenResult<()> {
        self.disable_level_with_type(
            login_type,
            login_id,
            DEFAULT_DISABLE_SERVICE,
            DEFAULT_DISABLE_LEVEL,
            time,
        )
        .await
    }

    /// Read disable level for a login type | 按登录类型读取禁用等级
    pub async fn get_disable_level_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        service: &str,
    ) -> SaTokenResult<i32> {
        let key = self.disable_key_ns(login_type, login_id, service);
        let value = self.dao.get_string(&key).await?;

        if let Some(v) = value {
            return v.parse::<i32>().map_err(|_| {
                SaTokenError::StorageError(format!("invalid disable level for key {key}"))
            });
        }

        if let Some(level) = self.authz_service().is_disabled(login_id, service).await? {
            return Ok(level);
        }

        Ok(NOT_DISABLE_LEVEL)
    }

    /// Whether disabled at/above level | 是否达到指定禁用等级
    pub async fn is_disable_level_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        service: &str,
        level: i32,
    ) -> SaTokenResult<bool> {
        let disable_level = self
            .get_disable_level_with_type(login_type, login_id, service)
            .await?;
        if disable_level == NOT_DISABLE_LEVEL {
            return Ok(false);
        }
        Ok(disable_level >= level)
    }

    /// Fail if disabled at/above level | 达到禁用等级则报错
    pub async fn check_disable_level_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        service: &str,
        level: i32,
    ) -> SaTokenResult<()> {
        let disable_level = self
            .get_disable_level_with_type(login_type, login_id, service)
            .await?;
        if disable_level == NOT_DISABLE_LEVEL {
            return Ok(());
        }
        if disable_level >= level {
            return Err(SaTokenError::AccountBanned(format!(
                "service={service} level={disable_level}"
            )));
        }
        Ok(())
    }

    /// Fail if any listed service is disabled | 任一服务被禁用则报错
    pub async fn check_disable_services_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        services: &[&str],
        level: i32,
    ) -> SaTokenResult<()> {
        for service in services {
            self.check_disable_level_with_type(login_type, login_id, service, level)
                .await?;
        }
        Ok(())
    }

    /// Clear disable for a login type | 按登录类型解除禁用
    pub async fn untie_disable_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        service: &str,
    ) -> SaTokenResult<()> {
        self.dao
            .delete(&self.disable_key_ns(login_type, login_id, service))
            .await?;

        let ns = self.account_ns(login_type, login_id);
        let event =
            crate::event::SaTokenEvent::unbanned(ns.as_str(), service).with_login_type(login_type);
        self.event_bus.publish(event).await;

        Ok(())
    }

    /// Disable at a level (default login type) | 分级禁用（默认登录类型）
    pub async fn disable_level(
        &self,
        login_id: &str,
        service: &str,
        level: i32,
        time: i64,
    ) -> SaTokenResult<()> {
        self.disable_level_with_type(LOGIN_TYPE_DEFAULT, login_id, service, level, time)
            .await
    }

    /// Disable account/service | 禁用账号或服务
    pub async fn disable(&self, login_id: &str, time: i64) -> SaTokenResult<()> {
        self.disable_with_type(LOGIN_TYPE_DEFAULT, login_id, time)
            .await
    }

    /// Read disable level | 读取禁用等级
    pub async fn get_disable_level(&self, login_id: &str, service: &str) -> SaTokenResult<i32> {
        self.get_disable_level_with_type(LOGIN_TYPE_DEFAULT, login_id, service)
            .await
    }

    /// Whether disabled at/above level | 是否达到指定禁用等级
    pub async fn is_disable_level(
        &self,
        login_id: &str,
        service: &str,
        level: i32,
    ) -> SaTokenResult<bool> {
        self.is_disable_level_with_type(LOGIN_TYPE_DEFAULT, login_id, service, level)
            .await
    }

    /// Fail if disabled at/above level | 达到禁用等级则报错
    pub async fn check_disable_level(
        &self,
        login_id: &str,
        service: &str,
        level: i32,
    ) -> SaTokenResult<()> {
        self.check_disable_level_with_type(LOGIN_TYPE_DEFAULT, login_id, service, level)
            .await
    }

    /// Fail if any listed service is disabled | 任一服务被禁用则报错
    pub async fn check_disable_services(
        &self,
        login_id: &str,
        services: &[&str],
        level: i32,
    ) -> SaTokenResult<()> {
        self.check_disable_services_with_type(LOGIN_TYPE_DEFAULT, login_id, services, level)
            .await
    }

    /// Clear disable flag | 解除禁用
    pub async fn untie_disable(&self, login_id: &str, service: &str) -> SaTokenResult<()> {
        self.untie_disable_with_type(LOGIN_TYPE_DEFAULT, login_id, service)
            .await
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
    async fn disable_and_check_level() {
        let mgr = manager();
        mgr.disable_level("u1", "login", 2, 60).await.unwrap();
        assert!(mgr.is_disable_level("u1", "login", 1).await.unwrap());
        assert!(mgr.is_disable_level("u1", "login", 2).await.unwrap());
        assert!(!mgr.is_disable_level("u1", "login", 3).await.unwrap());
        assert!(mgr.check_disable_level("u1", "login", 2).await.is_err());
        mgr.untie_disable("u1", "login").await.unwrap();
        assert_eq!(
            mgr.get_disable_level("u1", "login").await.unwrap(),
            NOT_DISABLE_LEVEL
        );
    }
}
