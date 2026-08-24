// Author: 金书记 | Author: Jin Shuji
//! Password grant callback. Core never checks passwords itself.
//! 密码模式回调。core 自身不校验密码。

use async_trait::async_trait;

use crate::error::SaTokenResult;

/// Password verification hook for the resource-owner password grant.
/// 资源所有者密码模式的密码校验钩子。
#[async_trait]
pub trait PasswordVerifier: Send + Sync {
    /// Return `Ok(())` only when the credentials are valid.
    /// 仅在凭据有效时返回 `Ok(())`。
    async fn verify_password(&self, username: &str, password: &str) -> SaTokenResult<()>;
}
