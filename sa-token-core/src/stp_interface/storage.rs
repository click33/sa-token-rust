// Author: 金书记 | Author: Jin Shuji
//
//! Storage-Backed Default Data Source | 基于存储的默认数据源
//!
//! ## 为什么需要这个薄包装
//!
//! 修复 B2-2 后 `GrantRepo` 已不认识 `StpInterface`，本类型看似只是它的转发层。
//! 但它承担了一个关键的设计职责：让「框架默认行为」也表达为一个 `StpInterface`，
//! 于是 [`crate::service::AuthzService`] 的读路径面对的永远是**一个** trait 对象，
//! 不需要在十几个读方法里各写一遍 `if let Some(iface) = ... else { repo }` 分支。
//!
//! ## Why this thin wrapper exists
//!
//! After the B2-2 fix, `GrantRepo` no longer knows about `StpInterface`, so this
//! type looks like a mere forwarder. Its real job is to express the *default*
//! behaviour as a `StpInterface` too, letting `AuthzService` always talk to a
//! single trait object instead of repeating an `Option` branch across a dozen
//! read methods.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::SaTokenResult;
use crate::repository::GrantRepo;
use crate::stp_interface::StpInterface;

/// 基于 storage 的默认 `StpInterface` 实现 | Default storage-backed `StpInterface`
pub struct StorageStpInterface {
    grant_repo: Arc<GrantRepo>,
}

impl std::fmt::Debug for StorageStpInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageStpInterface").finish()
    }
}

impl StorageStpInterface {
    /// 由授权仓储构造 | Build from the grant repository
    pub fn new(grant_repo: Arc<GrantRepo>) -> Self {
        Self { grant_repo }
    }

    /// 底层仓储引用 | Underlying repository reference
    pub fn grant_repo(&self) -> &Arc<GrantRepo> {
        &self.grant_repo
    }
}

#[async_trait]
impl StpInterface for StorageStpInterface {
    async fn get_permission_list(
        &self,
        login_id: &str,
        login_type: &str,
    ) -> SaTokenResult<Vec<String>> {
        self.grant_repo.get_permissions(login_type, login_id).await
    }

    async fn get_role_list(&self, login_id: &str, login_type: &str) -> SaTokenResult<Vec<String>> {
        self.grant_repo.get_roles(login_type, login_id).await
    }

    /// 读写同源，故接受框架写入 | Reads and writes share storage, so writes are accepted
    fn is_writable(&self) -> bool {
        true
    }
}
