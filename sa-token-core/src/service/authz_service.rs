// Author: 金书记 | Author: Jin Shuji
//
//! Authorization Service | 授权服务
//!
//! 权限与角色的**唯一**入口：读、写、校验、封禁回落全部经过本服务。
//! 这里也是**唯一**做「自定义数据源 vs 存储」优先级判断的地方。
//!
//! The single entry point for permissions and roles: reads, writes, checks and
//! the ban fallback all funnel through here. It is also the **only** place that
//! decides between a custom data source and storage.

use std::sync::Arc;

use crate::config::{GrantWritePolicy, SaTokenConfig};
use crate::context::SaTokenContext;
use crate::error::{SaTokenError, SaTokenResult};
use crate::event::{SaTokenEvent, SaTokenEventBus};
use crate::permission::{AntPermissionMatcher, ExactMatcher, PermissionMatcher};
use crate::repository::GrantRepo;
use crate::service::grant_cache::{GrantCache, GrantKind};
use crate::stp_interface::{StorageStpInterface, StpInterface};

/// 授权领域服务 | Authorization domain service
pub struct AuthzService {
    grant_repo: Arc<GrantRepo>,
    storage_iface: Arc<StorageStpInterface>,
    custom_iface: Option<Arc<dyn StpInterface>>,
    perm_matcher: Arc<dyn PermissionMatcher>,
    role_matcher: Arc<dyn PermissionMatcher>,
    cache: Option<Arc<GrantCache>>,
    write_policy: GrantWritePolicy,
    request_scope: bool,
    event_bus: SaTokenEventBus,
}

impl std::fmt::Debug for AuthzService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthzService")
            .field("has_custom_iface", &self.custom_iface.is_some())
            .field("write_policy", &self.write_policy)
            .field("request_scope", &self.request_scope)
            .finish()
    }
}

impl AuthzService {
    /// 构造授权服务 | Construct the authorization service
    pub fn new(
        grant_repo: Arc<GrantRepo>,
        config: &SaTokenConfig,
        event_bus: SaTokenEventBus,
        custom_iface: Option<Arc<dyn StpInterface>>,
    ) -> Self {
        let storage_iface = Arc::new(StorageStpInterface::new(Arc::clone(&grant_repo)));

        let role_matcher: Arc<dyn PermissionMatcher> = if config.role_wildcard {
            Arc::new(AntPermissionMatcher)
        } else {
            Arc::new(ExactMatcher)
        };

        Self {
            grant_repo,
            storage_iface,
            custom_iface,
            perm_matcher: Arc::new(AntPermissionMatcher),
            role_matcher,
            cache: GrantCache::from_config(config),
            write_policy: config.grant_write_policy,
            request_scope: config.grant_request_scope,
            event_bus,
        }
    }

    /// 替换权限匹配策略 | Replace the permission matching strategy
    pub fn with_permission_matcher(mut self, matcher: Arc<dyn PermissionMatcher>) -> Self {
        self.perm_matcher = matcher;
        self
    }

    /// 替换角色匹配策略 | Replace the role matching strategy
    pub fn with_role_matcher(mut self, matcher: Arc<dyn PermissionMatcher>) -> Self {
        self.role_matcher = matcher;
        self
    }

    /// 当前权限匹配策略 | Current permission matcher
    pub fn permission_matcher(&self) -> &Arc<dyn PermissionMatcher> {
        &self.perm_matcher
    }

    /// 当前角色匹配策略 | Current role matcher
    pub fn role_matcher(&self) -> &Arc<dyn PermissionMatcher> {
        &self.role_matcher
    }

    /// 是否已注入自定义数据源 | Whether a custom data source is injected
    pub fn has_custom_interface(&self) -> bool {
        self.custom_iface.is_some()
    }

    // ==================== 私有基础设施 | Private infrastructure ====================

    /// 生效的数据源：自定义优先，否则用存储外观。
    /// The effective data source, custom first.
    #[inline]
    fn iface(&self) -> &dyn StpInterface {
        match &self.custom_iface {
            Some(custom) => custom.as_ref(),
            None => self.storage_iface.as_ref() as &dyn StpInterface,
        }
    }

    /// 直接向数据源取数（不经任何缓存）| Fetch straight from the data source
    async fn fetch(
        &self,
        kind: GrantKind,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<String>> {
        match kind {
            GrantKind::Permission => self.iface().get_permission_list(login_id, login_type).await,
            GrantKind::Role => self.iface().get_role_list(login_id, login_type).await,
        }
    }

    /// 三级读取的统一实现：请求级快照 → 进程级缓存 → 数据源。
    /// Unified three-tier read: request snapshot, process cache, data source.
    async fn load(
        &self,
        kind: GrantKind,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Arc<[String]>> {
        let key = GrantCache::cache_key(kind, login_type, login_id);

        let scope = if self.request_scope {
            SaTokenContext::current_grant_scope()
        } else {
            None
        };
        if let Some(scope) = scope.as_ref() {
            if let Some(hit) = scope.get(&key) {
                return Ok(hit);
            }
        }

        let value: Arc<[String]> = match self.cache.as_ref() {
            Some(cache) => {
                cache
                    .get_or_load(key.clone(), || self.fetch(kind, login_type, login_id))
                    .await?
            }
            None => Arc::from(self.fetch(kind, login_type, login_id).await?),
        };

        if let Some(scope) = scope {
            scope.put(key, Arc::clone(&value));
        }

        Ok(value)
    }

    /// 写前校验 | Pre-write guard
    fn ensure_writable(&self, operation: &str) -> SaTokenResult<()> {
        let Some(custom) = self.custom_iface.as_ref() else {
            return Ok(());
        };
        if custom.is_writable() {
            return Ok(());
        }

        match self.write_policy {
            GrantWritePolicy::Allow => Ok(()),
            GrantWritePolicy::Warn => {
                tracing::warn!(
                    operation,
                    "grant write landed in storage, but the injected StpInterface is read-only \
                     (is_writable() == false), so reads will not observe it; implement \
                     is_writable() or set grant_write_policy = Reject"
                );
                Ok(())
            }
            GrantWritePolicy::Reject => Err(SaTokenError::ConfigError(format!(
                "{operation} rejected: the injected StpInterface is read-only \
                 (is_writable() == false) and grant_write_policy is Reject"
            ))),
        }
    }

    /// 写后处理：失效两级缓存 + 发布变更事件。
    /// Post-write hook: invalidate both cache tiers, then publish the event.
    async fn after_write(&self, login_type: &str, login_id: &str) {
        if let Some(cache) = self.cache.as_ref() {
            cache.invalidate_account(login_type, login_id);
        }

        if self.request_scope {
            if let Some(scope) = SaTokenContext::current_grant_scope() {
                scope.remove(&GrantCache::cache_key(
                    GrantKind::Permission,
                    login_type,
                    login_id,
                ));
                scope.remove(&GrantCache::cache_key(
                    GrantKind::Role,
                    login_type,
                    login_id,
                ));
            }
        }

        self.event_bus
            .publish(SaTokenEvent::grant_changed(login_id, login_type))
            .await;
    }

    // ==================== 读 | Reads ====================

    /// 读取权限列表（零拷贝）| Read the permission list without copying
    pub async fn get_permissions_arc(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Arc<[String]>> {
        self.load(GrantKind::Permission, login_type, login_id).await
    }

    /// 读取权限列表（`Vec` 形式）| Read the permission list as a `Vec`
    pub async fn get_permissions(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<String>> {
        Ok(self
            .get_permissions_arc(login_type, login_id)
            .await?
            .to_vec())
    }

    /// 读取角色列表（零拷贝）| Read the role list without copying
    pub async fn get_roles_arc(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Arc<[String]>> {
        self.load(GrantKind::Role, login_type, login_id).await
    }

    /// 读取角色列表（`Vec` 形式）| Read the role list as a `Vec`
    pub async fn get_roles(&self, login_type: &str, login_id: &str) -> SaTokenResult<Vec<String>> {
        Ok(self.get_roles_arc(login_type, login_id).await?.to_vec())
    }

    // ==================== 写 | Writes ====================

    /// 覆盖权限列表 | Overwrite the permission list
    pub async fn set_permissions(
        &self,
        login_type: &str,
        login_id: &str,
        permissions: &[String],
    ) -> SaTokenResult<()> {
        self.ensure_writable("set_permissions")?;
        self.grant_repo
            .set_permissions(login_type, login_id, permissions)
            .await?;
        self.after_write(login_type, login_id).await;
        Ok(())
    }

    /// 追加单个权限 | Append one permission
    pub async fn add_permission(
        &self,
        login_type: &str,
        login_id: &str,
        permission: String,
    ) -> SaTokenResult<()> {
        self.ensure_writable("add_permission")?;
        self.grant_repo
            .add_permission(login_type, login_id, permission)
            .await?;
        self.after_write(login_type, login_id).await;
        Ok(())
    }

    /// 移除单个权限 | Remove one permission
    pub async fn remove_permission(
        &self,
        login_type: &str,
        login_id: &str,
        permission: &str,
    ) -> SaTokenResult<()> {
        self.ensure_writable("remove_permission")?;
        self.grant_repo
            .remove_permission(login_type, login_id, permission)
            .await?;
        self.after_write(login_type, login_id).await;
        Ok(())
    }

    /// 清空权限（删键）| Clear permissions by deleting the key
    pub async fn clear_permissions(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        self.ensure_writable("clear_permissions")?;
        self.grant_repo
            .clear_permissions(login_type, login_id)
            .await?;
        self.after_write(login_type, login_id).await;
        Ok(())
    }

    /// 覆盖角色列表 | Overwrite the role list
    pub async fn set_roles(
        &self,
        login_type: &str,
        login_id: &str,
        roles: &[String],
    ) -> SaTokenResult<()> {
        self.ensure_writable("set_roles")?;
        self.grant_repo
            .set_roles(login_type, login_id, roles)
            .await?;
        self.after_write(login_type, login_id).await;
        Ok(())
    }

    /// 追加单个角色 | Append one role
    pub async fn add_role(
        &self,
        login_type: &str,
        login_id: &str,
        role: String,
    ) -> SaTokenResult<()> {
        self.ensure_writable("add_role")?;
        self.grant_repo.add_role(login_type, login_id, role).await?;
        self.after_write(login_type, login_id).await;
        Ok(())
    }

    /// 移除单个角色 | Remove one role
    pub async fn remove_role(
        &self,
        login_type: &str,
        login_id: &str,
        role: &str,
    ) -> SaTokenResult<()> {
        self.ensure_writable("remove_role")?;
        self.grant_repo
            .remove_role(login_type, login_id, role)
            .await?;
        self.after_write(login_type, login_id).await;
        Ok(())
    }

    /// 清空角色（删键）| Clear roles by deleting the key
    pub async fn clear_roles(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        self.ensure_writable("clear_roles")?;
        self.grant_repo.clear_roles(login_type, login_id).await?;
        self.after_write(login_type, login_id).await;
        Ok(())
    }

    // ==================== 权限校验 | Permission checks ====================

    /// 是否拥有指定权限 | Whether the account holds a permission
    pub async fn has_permission(
        &self,
        login_type: &str,
        login_id: &str,
        permission: &str,
    ) -> SaTokenResult<bool> {
        let owned = self.get_permissions_arc(login_type, login_id).await?;
        Ok(self.perm_matcher.matches(&owned, permission))
    }

    /// AND：全部权限都必须命中 | AND semantics
    pub async fn has_all_permissions(
        &self,
        login_type: &str,
        login_id: &str,
        permissions: &[&str],
    ) -> SaTokenResult<bool> {
        let owned = self.get_permissions_arc(login_type, login_id).await?;
        Ok(self.perm_matcher.matches_all(&owned, permissions))
    }

    /// OR：任一权限命中即可 | OR semantics
    pub async fn has_any_permission(
        &self,
        login_type: &str,
        login_id: &str,
        permissions: &[&str],
    ) -> SaTokenResult<bool> {
        let owned = self.get_permissions_arc(login_type, login_id).await?;
        Ok(self.perm_matcher.matches_any(&owned, permissions))
    }

    /// 校验权限，失败返回 `PermissionDeniedDetail`。
    /// Checks a permission, returning `PermissionDeniedDetail` on failure.
    pub async fn check_permission(
        &self,
        login_type: &str,
        login_id: &str,
        permission: &str,
    ) -> SaTokenResult<()> {
        if self
            .has_permission(login_type, login_id, permission)
            .await?
        {
            return Ok(());
        }
        tracing::debug!(login_type, login_id, permission, "permission check denied");
        Err(SaTokenError::PermissionDeniedDetail(permission.to_string()))
    }

    /// 校验多个权限（AND）| Check multiple permissions with AND semantics
    pub async fn check_all_permissions(
        &self,
        login_type: &str,
        login_id: &str,
        permissions: &[&str],
    ) -> SaTokenResult<()> {
        let owned = self.get_permissions_arc(login_type, login_id).await?;
        for required in permissions {
            if !self.perm_matcher.matches(&owned, required) {
                tracing::debug!(
                    login_type,
                    login_id,
                    permission = required,
                    "permission check denied (AND)"
                );
                return Err(SaTokenError::PermissionDeniedDetail(
                    (*required).to_string(),
                ));
            }
        }
        Ok(())
    }

    /// 校验多个权限（OR）| Check multiple permissions with OR semantics
    pub async fn check_any_permission(
        &self,
        login_type: &str,
        login_id: &str,
        permissions: &[&str],
    ) -> SaTokenResult<()> {
        if self
            .has_any_permission(login_type, login_id, permissions)
            .await?
        {
            return Ok(());
        }
        tracing::debug!(
            login_type,
            login_id,
            required = ?permissions,
            "permission check denied (OR)"
        );
        Err(SaTokenError::PermissionDeniedDetail(permissions.join(",")))
    }

    // ==================== 角色校验 | Role checks ====================

    /// 是否拥有指定角色 | Whether the account holds a role
    pub async fn has_role(
        &self,
        login_type: &str,
        login_id: &str,
        role: &str,
    ) -> SaTokenResult<bool> {
        let owned = self.get_roles_arc(login_type, login_id).await?;
        Ok(self.role_matcher.matches(&owned, role))
    }

    /// AND：全部角色都必须命中 | AND semantics
    pub async fn has_all_roles(
        &self,
        login_type: &str,
        login_id: &str,
        roles: &[&str],
    ) -> SaTokenResult<bool> {
        let owned = self.get_roles_arc(login_type, login_id).await?;
        Ok(self.role_matcher.matches_all(&owned, roles))
    }

    /// OR：任一角色命中即可 | OR semantics
    pub async fn has_any_role(
        &self,
        login_type: &str,
        login_id: &str,
        roles: &[&str],
    ) -> SaTokenResult<bool> {
        let owned = self.get_roles_arc(login_type, login_id).await?;
        Ok(self.role_matcher.matches_any(&owned, roles))
    }

    /// 校验角色 | Check a role
    pub async fn check_role(
        &self,
        login_type: &str,
        login_id: &str,
        role: &str,
    ) -> SaTokenResult<()> {
        if self.has_role(login_type, login_id, role).await? {
            return Ok(());
        }
        tracing::debug!(login_type, login_id, role, "role check denied");
        Err(SaTokenError::RoleDenied(role.to_string()))
    }

    /// 校验多个角色（AND）| Check multiple roles with AND semantics
    pub async fn check_all_roles(
        &self,
        login_type: &str,
        login_id: &str,
        roles: &[&str],
    ) -> SaTokenResult<()> {
        let owned = self.get_roles_arc(login_type, login_id).await?;
        for required in roles {
            if !self.role_matcher.matches(&owned, required) {
                tracing::debug!(
                    login_type,
                    login_id,
                    role = required,
                    "role check denied (AND)"
                );
                return Err(SaTokenError::RoleDenied((*required).to_string()));
            }
        }
        Ok(())
    }

    /// 校验多个角色（OR）| Check multiple roles with OR semantics
    pub async fn check_any_role(
        &self,
        login_type: &str,
        login_id: &str,
        roles: &[&str],
    ) -> SaTokenResult<()> {
        if self.has_any_role(login_type, login_id, roles).await? {
            return Ok(());
        }
        tracing::debug!(login_type, login_id, required = ?roles, "role check denied (OR)");
        Err(SaTokenError::RoleDenied(roles.join(",")))
    }

    // ==================== 封禁回落 | Ban fallback ====================

    /// 向数据源查询封禁等级；`None` 表示未封禁。
    ///
    /// 只在**存储中查不到**封禁记录时被 `disable.rs` 调用。
    ///
    /// Queries the data source for a ban level; `None` means not banned.
    pub async fn is_disabled(&self, login_id: &str, service: &str) -> SaTokenResult<Option<i32>> {
        match self.custom_iface.as_ref() {
            Some(custom) => custom.is_disabled(login_id, service).await,
            None => Ok(None),
        }
    }

    // ==================== 缓存运维 | Cache maintenance ====================

    /// 失效某账号的权限与角色缓存。
    ///
    /// Invalidates an account's cached permissions and roles.
    pub fn invalidate_account(&self, login_type: &str, login_id: &str) {
        if let Some(cache) = self.cache.as_ref() {
            cache.invalidate_account(login_type, login_id);
        }
        if self.request_scope {
            if let Some(scope) = SaTokenContext::current_grant_scope() {
                scope.remove(&GrantCache::cache_key(
                    GrantKind::Permission,
                    login_type,
                    login_id,
                ));
                scope.remove(&GrantCache::cache_key(
                    GrantKind::Role,
                    login_type,
                    login_id,
                ));
            }
        }
    }

    /// 清空全部授权缓存 | Clear the entire grant cache
    pub fn invalidate_all(&self) {
        if let Some(cache) = self.cache.as_ref() {
            cache.clear();
        }
        if self.request_scope {
            if let Some(scope) = SaTokenContext::current_grant_scope() {
                scope.clear();
            }
        }
    }

    /// 当前缓存条目数（诊断用）| Cached entry count for diagnostics
    pub fn cache_len(&self) -> usize {
        self.cache.as_ref().map_or(0, |c| c.len())
    }
}
