// Author: 金书记 | Author: Jin Shuji
//
//! Grant Repository (storage only) | 授权数据仓储（仅存储）
//!
//! 本仓储只做一件事：把权限/角色字符串列表读写到 `SaTokenDao`。
//! 它**不认识** `StpInterface`，也不做任何数据源优先级判断。
//!
//! This repository does exactly one thing: read/write permission and role string
//! lists through `SaTokenDao`. It is deliberately unaware of `StpInterface` and
//! performs no data-source precedence logic.
//!
//! ## 为什么移除了 `StpInterface` 分支（B2-2）
//!
//! 早期版本在此处优先走 `StpInterface` 回调，导致两个严重后果：
//!
//! 1. **数据污染**：`add_permission` 的 read-modify-write 会「读外部回调、写 storage」，
//!    一次调用就把外部数据源的整份权限列表复制进 storage。
//! 2. **无限递归**：`StorageStpInterface::get_permission_list` → `GrantRepo::get_permissions`
//!    → `stp_interface.get_permission_list` 构成回环，栈溢出。
//!
//! 因此优先级判断被上移到 [`crate::service::AuthzService`] 唯一一处，
//! 本层退化为「storage 这个具体数据源」的实现细节。

use std::sync::Arc;

use crate::dao::SaTokenDao;
use crate::error::SaTokenResult;

/// 权限 / 角色数据仓储（纯存储）| Permission and role repository (storage only)
pub struct GrantRepo {
    dao: Arc<SaTokenDao>,
}

impl std::fmt::Debug for GrantRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GrantRepo { .. }")
    }
}

impl GrantRepo {
    /// 构造仓储 | Construct the repository
    ///
    /// 仅需 `dao`：键构造与序列化都由 `SaTokenDao` 收口，
    /// 缓存与数据源优先级由 `AuthzService` 负责，本层无需 config。
    ///
    /// Only `dao` is needed: key building and serialization are funnelled through
    /// `SaTokenDao`, while caching and precedence belong to `AuthzService`.
    pub fn new(dao: Arc<SaTokenDao>) -> Self {
        Self { dao }
    }

    /// 权限键 | Permission key
    #[inline]
    fn permission_key(&self, login_type: &str, login_id: &str) -> String {
        self.dao.keys().permission(login_type, login_id)
    }

    /// 角色键 | Role key
    #[inline]
    fn role_key(&self, login_type: &str, login_id: &str) -> String {
        self.dao.keys().role(login_type, login_id)
    }

    // ==================== 权限 | Permissions ====================

    /// 读取权限列表（键缺失视为空列表）| Read the permission list, absent = empty
    pub async fn get_permissions(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<String>> {
        self.dao
            .get_string_list(&self.permission_key(login_type, login_id))
            .await
    }

    /// 覆盖写入权限列表（永久保存，不设 TTL）| Overwrite the permission list
    pub async fn set_permissions(
        &self,
        login_type: &str,
        login_id: &str,
        permissions: &[String],
    ) -> SaTokenResult<()> {
        self.dao
            .set_string_list(
                &self.permission_key(login_type, login_id),
                permissions,
                None,
            )
            .await
    }

    /// 追加单个权限（已存在则不写存储）| Append one permission, no write when present
    pub async fn add_permission(
        &self,
        login_type: &str,
        login_id: &str,
        permission: String,
    ) -> SaTokenResult<()> {
        let key = self.permission_key(login_type, login_id);
        let mut list = self.dao.get_string_list(&key).await?;
        if !list.contains(&permission) {
            list.push(permission);
            self.dao.set_string_list(&key, &list, None).await?;
        }
        Ok(())
    }

    /// 移除单个权限（不存在时不写存储）| Remove one permission, no write when absent
    pub async fn remove_permission(
        &self,
        login_type: &str,
        login_id: &str,
        permission: &str,
    ) -> SaTokenResult<()> {
        let key = self.permission_key(login_type, login_id);
        let mut list = self.dao.get_string_list(&key).await?;
        let before = list.len();
        list.retain(|p| p != permission);
        if list.len() != before {
            self.dao.set_string_list(&key, &list, None).await?;
        }
        Ok(())
    }

    /// 清空权限（直接删键）| Clear permissions by deleting the key
    pub async fn clear_permissions(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        self.dao
            .delete(&self.permission_key(login_type, login_id))
            .await
    }

    // ==================== 角色 | Roles ====================

    /// 读取角色列表（键缺失视为空列表）| Read the role list, absent = empty
    pub async fn get_roles(&self, login_type: &str, login_id: &str) -> SaTokenResult<Vec<String>> {
        self.dao
            .get_string_list(&self.role_key(login_type, login_id))
            .await
    }

    /// 覆盖写入角色列表（永久保存）| Overwrite the role list
    pub async fn set_roles(
        &self,
        login_type: &str,
        login_id: &str,
        roles: &[String],
    ) -> SaTokenResult<()> {
        self.dao
            .set_string_list(&self.role_key(login_type, login_id), roles, None)
            .await
    }

    /// 追加单个角色（已存在则跳过）| Append one role, no-op if present
    pub async fn add_role(
        &self,
        login_type: &str,
        login_id: &str,
        role: String,
    ) -> SaTokenResult<()> {
        let key = self.role_key(login_type, login_id);
        let mut list = self.dao.get_string_list(&key).await?;
        if !list.contains(&role) {
            list.push(role);
            self.dao.set_string_list(&key, &list, None).await?;
        }
        Ok(())
    }

    /// 移除单个角色 | Remove one role
    pub async fn remove_role(
        &self,
        login_type: &str,
        login_id: &str,
        role: &str,
    ) -> SaTokenResult<()> {
        let key = self.role_key(login_type, login_id);
        let mut list = self.dao.get_string_list(&key).await?;
        let before = list.len();
        list.retain(|r| r != role);
        if list.len() != before {
            self.dao.set_string_list(&key, &list, None).await?;
        }
        Ok(())
    }

    /// 清空角色（直接删键）| Clear roles by deleting the key
    pub async fn clear_roles(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        self.dao.delete(&self.role_key(login_type, login_id)).await
    }
}
