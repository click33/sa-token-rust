//! Session 仓储：Account-Session、Token-Session、终端列表。
//!
//! 键构造统一以 [`AccountNs`] 为入参，杜绝「把已命名空间化的 id 再当作
//! login_id 传一次」这类二次拼接错误（A3-2 反模式）。
//!
//! Session repository for account sessions, token sessions and the terminal
//! list. Every key is built from an [`AccountNs`], which structurally prevents
//! the "namespaced id passed again as a login id" bug class.

use std::sync::Arc;
use std::time::Duration;

use crate::config::SaTokenConfig;
use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use crate::keys::{AccountNs, LoginId, SaKeys};
use crate::session::{SaSession, SaTerminalInfo};
use crate::token::TokenValue;

/// Session 读写与终端维护 | Session persistence and terminal bookkeeping
pub struct SessionRepo {
    dao: Arc<SaTokenDao>,
    config: Arc<SaTokenConfig>,
}

impl std::fmt::Debug for SessionRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionRepo { .. }")
    }
}

impl SessionRepo {
    /// 构造仓储 | Construct the repository
    pub fn new(dao: Arc<SaTokenDao>, config: Arc<SaTokenConfig>) -> Self {
        Self { dao, config }
    }

    /// Account-Session 的 TTL。
    fn session_ttl(&self) -> Option<Duration> {
        self.dao.default_ttl()
    }

    /// 由 (login_type, login_id) 构造账号命名空间。
    fn ns(login_type: &str, login_id: &str) -> SaTokenResult<AccountNs> {
        let id =
            LoginId::try_new(login_id).map_err(|e| SaTokenError::ConfigError(e.to_string()))?;
        Ok(SaKeys::account_ns(login_type, &id))
    }

    /// Account-Session 存储键 | Account session storage key
    fn account_session_key(&self, ns: &AccountNs) -> SaTokenResult<String> {
        self.dao
            .keys()
            .session_by_ns(ns)
            .map_err(|e| SaTokenError::ConfigError(e.to_string()))
    }

    // ==================== Account-Session ====================

    /// 按命名空间读取账号 Session，缺失时返回空 Session（不写入存储）。
    pub async fn get_by_ns(&self, ns: &AccountNs) -> SaTokenResult<SaSession> {
        let key = self.account_session_key(ns)?;
        if let Some(session) = self.dao.get_object::<SaSession>(&key).await? {
            return Ok(session);
        }
        Ok(SaSession::new(ns.as_str()))
    }

    /// 按 (login_type, login_id) 读取账号 Session。
    pub async fn get_account_session(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<SaSession> {
        let ns = Self::ns(login_type, login_id)?;
        self.get_by_ns(&ns).await
    }

    /// 读取原始序列化快照，供补偿器恢复旧值使用（修 B1-8）。
    pub async fn snapshot_account_session(&self, ns: &AccountNs) -> SaTokenResult<Option<String>> {
        let key = self.account_session_key(ns)?;
        self.dao.get_string(&key).await
    }

    /// 按命名空间写入账号 Session | Persist an account session by namespace
    pub async fn save_by_ns(&self, ns: &AccountNs, session: &SaSession) -> SaTokenResult<()> {
        let key = self.account_session_key(ns)?;
        self.dao.set_object(&key, session, self.session_ttl()).await
    }

    /// 按 (login_type, login_id) 写入账号 Session。
    pub async fn save_account_session(
        &self,
        login_type: &str,
        login_id: &str,
        session: &SaSession,
    ) -> SaTokenResult<()> {
        let ns = Self::ns(login_type, login_id)?;
        self.save_by_ns(&ns, session).await
    }

    /// 直接按 Session 自身的 id 回写（修 B1-9 的核心）。
    pub async fn save_session_object(&self, session: &SaSession) -> SaTokenResult<()> {
        let ns = AccountNs::from_trusted(session.id.clone());
        self.save_by_ns(&ns, session).await
    }

    /// 按命名空间删除账号 Session | Delete an account session by namespace
    pub async fn delete_by_ns(&self, ns: &AccountNs) -> SaTokenResult<()> {
        let key = self.account_session_key(ns)?;
        self.dao.delete(&key).await
    }

    /// 按 (login_type, login_id) 删除账号 Session。
    pub async fn delete_account_session(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<()> {
        let ns = Self::ns(login_type, login_id)?;
        self.delete_by_ns(&ns).await
    }

    // ==================== 终端列表 | Terminal list ====================

    /// 追加终端信息（读-改-写）。
    pub async fn add_terminal(
        &self,
        ns: &AccountNs,
        terminal: SaTerminalInfo,
    ) -> SaTokenResult<()> {
        let mut session = self.get_by_ns(ns).await?;
        session.add_terminal(terminal);
        self.save_by_ns(ns, &session).await
    }

    /// 移除终端信息，返回是否确实移除。
    pub async fn remove_terminal(&self, ns: &AccountNs, token: &str) -> SaTokenResult<bool> {
        let mut session = self.get_by_ns(ns).await?;
        if session.remove_terminal(token).is_none() {
            return Ok(false);
        }
        self.save_by_ns(ns, &session).await?;
        Ok(true)
    }

    /// 终端数量 | Terminal count
    pub async fn terminal_count(&self, ns: &AccountNs) -> SaTokenResult<usize> {
        Ok(self.get_by_ns(ns).await?.terminal_count())
    }

    /// 按设备类型过滤终端列表 | Terminal list filtered by device type
    pub async fn get_terminal_list(
        &self,
        ns: &AccountNs,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<SaTerminalInfo>> {
        Ok(self
            .get_by_ns(ns)
            .await?
            .get_terminal_list_by_device_type(device_type))
    }

    /// 按设备类型过滤 token 列表 | Token list filtered by device type
    pub async fn get_token_list(
        &self,
        ns: &AccountNs,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<String>> {
        Ok(self
            .get_by_ns(ns)
            .await?
            .get_token_value_list_by_device_type(device_type))
    }

    /// 按 token 反查单个终端 | Look up a single terminal by token
    pub async fn get_terminal(
        &self,
        ns: &AccountNs,
        token: &str,
    ) -> SaTokenResult<Option<SaTerminalInfo>> {
        Ok(self.get_by_ns(ns).await?.get_terminal(token).cloned())
    }

    // ==================== Token-Session ====================

    /// Token-Session 的 TTL 与 token 本体一致（token 消失后 session 无意义）。
    fn token_session_ttl(&self) -> Option<Duration> {
        self.dao.default_ttl()
    }

    /// 立即创建空的 Token-Session（`right_now_create_token_session`）。
    pub async fn create_token_session(&self, token: &TokenValue) -> SaTokenResult<()> {
        let session = SaSession::new(format!("token-session:{}", token.as_str()));
        self.save_token_session(token, &session).await
    }

    /// 写入 Token-Session | Persist a token session
    pub async fn save_token_session(
        &self,
        token: &TokenValue,
        session: &SaSession,
    ) -> SaTokenResult<()> {
        let key = self.dao.keys().token_session(token.as_str());
        self.dao
            .set_object(&key, session, self.token_session_ttl())
            .await
    }

    /// 读取 Token-Session | Read a token session
    pub async fn get_token_session(&self, token: &TokenValue) -> SaTokenResult<Option<SaSession>> {
        let key = self.dao.keys().token_session(token.as_str());
        self.dao.get_object(&key).await
    }

    /// 删除 Token-Session | Delete a token session
    pub async fn delete_token_session(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.dao
            .delete(&self.dao.keys().token_session(token.as_str()))
            .await
    }

    /// Token-Session 存储键（供补偿器登记删除动作）。
    pub fn token_session_key(&self, token: &str) -> String {
        self.dao.keys().token_session(token)
    }

    /// 配置引用（`is_logout_keep_token_session` 等判定用）。
    pub fn config(&self) -> &Arc<SaTokenConfig> {
        &self.config
    }
}
