// Author: 金书记
//
//! 多账号体系门面：绑定 login_type + Manager 克隆（内部字段均为 Arc，Clone 廉价）。
//! Multi-account facade: binds login_type + a cloned Manager (fields are Arc; Clone is cheap).
//! 无进程级 HashMap，避免与 Manager 形成引用环。
//! No process-wide HashMap, avoiding a reference cycle with Manager.

use std::sync::Arc;

use crate::disable;
use crate::error::SaTokenResult;
use crate::keys::SaKeys;
use crate::manager::SaTokenManager;
use crate::session::{SaSession, SaTerminalInfo};
use crate::token::TokenValue;

/// 绑定某一 login_type 的账号逻辑门面
/// Account-logic facade bound to one login_type
#[derive(Clone)]
pub struct SaLogic {
    login_type: Arc<str>,
    manager: SaTokenManager,
}

impl std::fmt::Debug for SaLogic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SaLogic { .. }")
    }
}

impl SaLogic {
    /// 创建门面（廉价 Clone）
    /// Create facade (cheap to Clone)
    pub fn new(login_type: impl AsRef<str>, manager: SaTokenManager) -> Self {
        Self {
            login_type: Arc::from(login_type.as_ref()),
            manager,
        }
    }

    /// Account system / login type | 账号体系/登录类型
    pub fn login_type(&self) -> &str {
        &self.login_type
    }

    /// Underlying manager | 底层管理器
    pub fn manager(&self) -> &SaTokenManager {
        &self.manager
    }

    /// Key layout helper | 键布局辅助
    pub fn keys(&self) -> &SaKeys {
        self.manager.keys()
    }

    /// Login and issue a token | 登录并签发 Token
    pub async fn login(&self, login_id: impl Into<String>) -> SaTokenResult<TokenValue> {
        self.manager
            .login_with_options(
                login_id,
                Some(self.login_type.to_string()),
                None,
                None,
                None,
                None,
            )
            .await
    }

    /// Login with device label | 带设备标识登录
    pub async fn login_with_device(
        &self,
        login_id: impl Into<String>,
        device: Option<String>,
        extra: Option<serde_json::Value>,
    ) -> SaTokenResult<TokenValue> {
        self.manager
            .login_with_options(
                login_id,
                Some(self.login_type.to_string()),
                device,
                extra,
                None,
                None,
            )
            .await
    }

    /// Logout current token | 登出当前 Token
    pub async fn logout(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.manager.logout(token).await
    }

    /// Logout all tokens of a login id | 登出某登录 ID 的全部 Token
    pub async fn logout_by_login_id(&self, login_id: &str) -> SaTokenResult<()> {
        self.manager
            .logout_by_login_id(&self.login_type, login_id)
            .await
    }

    /// Kick out and optionally notify | 踢下线并可通知
    pub async fn kick_out(&self, login_id: &str) -> SaTokenResult<()> {
        self.manager.kick_out(&self.login_type, login_id).await
    }

    /// Resolve login id from token | 从 Token 解析登录 ID
    pub async fn get_login_id(&self, token: &TokenValue) -> SaTokenResult<String> {
        Ok(self
            .manager
            .get_token_info(token)
            .await?
            .login_id
            .to_string())
    }

    /// Whether the token is valid | Token 是否有效
    pub async fn is_valid(&self, token: &TokenValue) -> bool {
        self.manager.is_valid(token).await
    }

    /// Load account session | 加载账号 Session
    pub async fn get_session(&self, login_id: &str) -> SaTokenResult<SaSession> {
        self.manager
            .get_session_with_type(&self.login_type, login_id)
            .await
    }

    /// Persist account session | 持久化账号 Session
    pub async fn save_session(&self, login_id: &str, session: &SaSession) -> SaTokenResult<()> {
        self.manager
            .save_session_with_type(&self.login_type, login_id, session)
            .await
    }

    /// Delete account session | 删除账号 Session
    pub async fn delete_session(&self, login_id: &str) -> SaTokenResult<()> {
        self.manager
            .delete_session_with_type(&self.login_type, login_id)
            .await
    }

    /// List terminals for the account | 列出账号终端
    pub async fn get_terminal_list(
        &self,
        login_id: &str,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<SaTerminalInfo>> {
        self.manager
            .get_terminal_list(&self.login_type, login_id, device_type)
            .await
    }

    /// Terminal info for a token | 按 Token 查终端信息
    pub async fn get_terminal_info_by_token(
        &self,
        token: &TokenValue,
    ) -> SaTokenResult<Option<SaTerminalInfo>> {
        self.manager.get_terminal_info_by_token(token).await
    }

    // ---------- 权限 | Permissions ----------

    /// 获取权限列表 | Permission list
    pub async fn get_permissions(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        self.manager
            .get_permissions_with_type(&self.login_type, login_id)
            .await
    }

    /// 覆盖权限列表 | Overwrite the permission list
    pub async fn set_permissions(&self, login_id: &str, perms: Vec<String>) -> SaTokenResult<()> {
        self.manager
            .set_permissions_with_type(&self.login_type, login_id, perms)
            .await
    }

    /// 追加单个权限（B2-35 新增）| Append one permission (new)
    pub async fn add_permission(
        &self,
        login_id: &str,
        permission: impl Into<String>,
    ) -> SaTokenResult<()> {
        self.manager
            .add_permission_with_type(&self.login_type, login_id, permission.into())
            .await
    }

    /// 移除单个权限（B2-35 新增）| Remove one permission (new)
    pub async fn remove_permission(&self, login_id: &str, permission: &str) -> SaTokenResult<()> {
        self.manager
            .remove_permission_with_type(&self.login_type, login_id, permission)
            .await
    }

    /// 清空权限（B2-35 新增）| Clear permissions (new)
    pub async fn clear_permissions(&self, login_id: &str) -> SaTokenResult<()> {
        self.manager
            .clear_permissions_with_type(&self.login_type, login_id)
            .await
    }

    /// 单个权限校验（B2-27 新增）| Single permission check (new)
    pub async fn has_permission(&self, login_id: &str, permission: &str) -> SaTokenResult<bool> {
        self.manager
            .authz_service()
            .has_permission(&self.login_type, login_id, permission)
            .await
    }

    /// 权限校验，不足则返回 `Err`（B2-27 新增）| Permission check returning `Err` (new)
    pub async fn check_permission(&self, login_id: &str, permission: &str) -> SaTokenResult<()> {
        self.manager
            .authz_service()
            .check_permission(&self.login_type, login_id, permission)
            .await
    }

    /// 批量权限校验（AND，B2-27 新增）| Batch AND permission check (new)
    pub async fn has_all_permissions(
        &self,
        login_id: &str,
        permissions: &[&str],
    ) -> SaTokenResult<bool> {
        self.manager
            .authz_service()
            .has_all_permissions(&self.login_type, login_id, permissions)
            .await
    }

    /// 批量权限校验（OR，B2-27 新增）| Batch OR permission check (new)
    pub async fn has_any_permission(
        &self,
        login_id: &str,
        permissions: &[&str],
    ) -> SaTokenResult<bool> {
        self.manager
            .authz_service()
            .has_any_permission(&self.login_type, login_id, permissions)
            .await
    }

    // ---------- 角色 | Roles ----------

    /// 获取角色列表 | Role list
    pub async fn get_roles(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        self.manager
            .get_roles_with_type(&self.login_type, login_id)
            .await
    }

    /// 覆盖角色列表 | Overwrite the role list
    pub async fn set_roles(&self, login_id: &str, roles: Vec<String>) -> SaTokenResult<()> {
        self.manager
            .set_roles_with_type(&self.login_type, login_id, roles)
            .await
    }

    /// 追加单个角色（B2-35 新增）| Append one role (new)
    pub async fn add_role(&self, login_id: &str, role: impl Into<String>) -> SaTokenResult<()> {
        self.manager
            .add_role_with_type(&self.login_type, login_id, role.into())
            .await
    }

    /// 移除单个角色（B2-35 新增）| Remove one role (new)
    pub async fn remove_role(&self, login_id: &str, role: &str) -> SaTokenResult<()> {
        self.manager
            .remove_role_with_type(&self.login_type, login_id, role)
            .await
    }

    /// 清空角色（B2-35 新增）| Clear roles (new)
    pub async fn clear_roles(&self, login_id: &str) -> SaTokenResult<()> {
        self.manager
            .clear_roles_with_type(&self.login_type, login_id)
            .await
    }

    /// 单个角色校验（B2-27 新增）| Single role check (new)
    pub async fn has_role(&self, login_id: &str, role: &str) -> SaTokenResult<bool> {
        self.manager
            .authz_service()
            .has_role(&self.login_type, login_id, role)
            .await
    }

    /// 角色校验，不足则返回 `Err`（B2-27 新增）| Role check returning `Err` (new)
    pub async fn check_role(&self, login_id: &str, role: &str) -> SaTokenResult<()> {
        self.manager
            .authz_service()
            .check_role(&self.login_type, login_id, role)
            .await
    }

    /// 批量角色校验（AND，B2-27 新增）| Batch AND role check (new)
    pub async fn has_all_roles(&self, login_id: &str, roles: &[&str]) -> SaTokenResult<bool> {
        self.manager
            .authz_service()
            .has_all_roles(&self.login_type, login_id, roles)
            .await
    }

    /// 批量角色校验（OR，B2-27 新增）| Batch OR role check (new)
    pub async fn has_any_role(&self, login_id: &str, roles: &[&str]) -> SaTokenResult<bool> {
        self.manager
            .authz_service()
            .has_any_role(&self.login_type, login_id, roles)
            .await
    }

    // ---------- 封禁 | Disable ----------

    /// Disable account/service | 禁用账号或服务
    pub async fn disable(&self, login_id: &str, time: i64) -> SaTokenResult<()> {
        self.manager
            .disable_with_type(&self.login_type, login_id, time)
            .await
    }

    /// Disable at a level (default login type) | 分级禁用（默认登录类型）
    pub async fn disable_level(
        &self,
        login_id: &str,
        service: &str,
        level: i32,
        time: i64,
    ) -> SaTokenResult<()> {
        self.manager
            .disable_level_with_type(&self.login_type, login_id, service, level, time)
            .await
    }

    /// Fail if account is disabled | 账号被禁用则报错
    pub async fn check_disable(&self, login_id: &str) -> SaTokenResult<()> {
        self.manager
            .check_disable_level_with_type(
                &self.login_type,
                login_id,
                disable::DEFAULT_DISABLE_SERVICE,
                disable::MIN_DISABLE_LEVEL,
            )
            .await
    }

    /// Read disable level | 读取禁用等级
    pub async fn get_disable_level(&self, login_id: &str, service: &str) -> SaTokenResult<i32> {
        self.manager
            .get_disable_level_with_type(&self.login_type, login_id, service)
            .await
    }

    /// Clear disable flag | 解除禁用
    pub async fn untie_disable(&self, login_id: &str, service: &str) -> SaTokenResult<()> {
        self.manager
            .untie_disable_with_type(&self.login_type, login_id, service)
            .await
    }

    // ---------- 二级认证 | Safe auth ----------

    /// Open secondary auth window | 开启二级认证窗口
    pub async fn open_safe(
        &self,
        token: &TokenValue,
        service: &str,
        safe_time: i64,
    ) -> SaTokenResult<()> {
        self.manager.open_safe(token, service, safe_time).await
    }

    /// Fail if secondary auth missing | 未通过二级认证则报错
    pub async fn check_safe(&self, token: &TokenValue, service: &str) -> SaTokenResult<()> {
        self.manager.check_safe(token, service).await
    }

    /// Whether secondary auth is active | 二级认证是否有效
    pub async fn is_safe(&self, token: &TokenValue, service: &str) -> SaTokenResult<bool> {
        self.manager.is_safe(token, service).await
    }

    /// Close secondary auth window | 关闭二级认证窗口
    pub async fn close_safe(&self, token: &TokenValue, service: &str) -> SaTokenResult<()> {
        self.manager.close_safe(token, service).await
    }

    // ---------- Token Session ----------

    /// Load token-scoped session | 加载 Token 级 Session
    pub async fn get_token_session(&self, token: &TokenValue) -> SaTokenResult<SaSession> {
        self.manager.get_token_session(token).await
    }

    /// Load anonymous token session | 加载匿名 Token Session
    pub async fn get_anon_token_session(&self, token: &TokenValue) -> SaTokenResult<SaSession> {
        self.manager.get_anon_token_session(token).await
    }

    /// `save_token_session` — save token session | `save_token_session`
    pub async fn save_token_session(
        &self,
        token: &TokenValue,
        session: &SaSession,
    ) -> SaTokenResult<()> {
        self.manager.save_token_session(token, session).await
    }

    /// `delete_token_session` — delete token session | `delete_token_session`
    pub async fn delete_token_session(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.manager.delete_token_session(token).await
    }

    // ---------- 身份临时切换 | Identity switch ----------

    /// 必须走 B3 单轨突变，否则 task-local 路径静默失效。
    /// Must use B3 single-track mutation or task-local switch silently fails.
    pub fn switch_to(&self, login_id: impl Into<String>) {
        let target = login_id.into();
        crate::context::SaTokenContext::with_current_mut(|inner| {
            inner.switch_login_id = Some(target);
        });
    }

    /// End identity switch | 结束身份切换
    pub fn end_switch(&self) {
        crate::context::SaTokenContext::with_current_mut(|inner| {
            inner.switch_login_id = None;
        });
    }

    /// Whether identity is switched | 是否处于身份切换中
    pub fn is_switch(&self) -> bool {
        crate::context::SaTokenContext::get_current()
            .and_then(|c| c.switch_login_id())
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_storage_memory::MemoryStorage;

    fn make_manager() -> SaTokenManager {
        SaTokenManager::new(
            Arc::new(MemoryStorage::new()),
            crate::SaTokenConfig::default(),
        )
    }

    #[tokio::test]
    async fn test_sa_logic_permission_isolation() {
        let mgr = make_manager();
        let admin = SaLogic::new("admin", mgr.clone());
        let user = SaLogic::new("user", mgr);

        admin
            .set_permissions("10001", vec!["admin:read".to_string()])
            .await
            .unwrap();
        user.set_permissions("10001", vec!["user:read".to_string()])
            .await
            .unwrap();

        assert_eq!(
            admin.get_permissions("10001").await.unwrap(),
            vec!["admin:read".to_string()]
        );
        assert_eq!(
            user.get_permissions("10001").await.unwrap(),
            vec!["user:read".to_string()]
        );
    }

    #[tokio::test]
    async fn test_sa_logic_clone_is_independent_facade() {
        let mgr = make_manager();
        let a = SaLogic::new("shared", mgr.clone());
        let b = SaLogic::new("shared", mgr);
        assert_eq!(a.login_type(), b.login_type());
        assert_eq!(a.login_type(), "shared");
    }
}
