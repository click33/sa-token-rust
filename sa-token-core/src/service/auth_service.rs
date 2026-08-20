//! 认证服务：登录、登出、踢人、续期的唯一业务入口。
//!
//! 本模块承担「跨仓储编排」职责：单个仓储只保证单键操作正确，
//! 而一次登录要同时改动 6 个键、一次下线要同时改动 5 个键，
//! 这些复合操作的顺序、失败补偿与并发保护全部收敛在这里。
//!
//! Authentication service: the single entry point for login, logout, kickout and
//! renewal. Because `SaStorage` only guarantees single-key atomicity, a login is
//! made near-transactional through staged writes, reverse compensation, and a
//! compare-and-swap commit point on the `login:token` mapping.

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};

use crate::config::{LogoutMode, LogoutRange, ReplacedLoginExitMode, ReplacedRange, SaTokenConfig};
use crate::dao::SaTokenDao;
use crate::distributed::DistributedSessionManager;
use crate::error::{SaTokenError, SaTokenResult};
use crate::event::{SaTokenEvent, SaTokenEventBus};
use crate::keys::{AccountNs, LoginId, SaKeys};
use crate::nonce::NonceManager;
use crate::online::OnlineManager;
use crate::refresh::RefreshTokenManager;
use crate::repository::{SessionRepo, TokenIdMapping, TokenRepo};
use crate::service::compensate::LoginCompensator;
use crate::service::login_request::LoginRequest;
use crate::session::SaTerminalInfo;
use crate::token::{TokenGenerator, TokenInfo, TokenValue};

/// 下线时解析出的账号身份 | Account identity resolved during logout
struct LogoutIdentity {
    login_type: String,
    login_id: String,
    /// token 体是否存在（决定是否需要清理终端与 Session）
    /// Whether the token body existed, deciding terminal/session cleanup
    _body_existed: bool,
}

/// 认证领域服务 | Authentication domain service
pub struct AuthService {
    dao: Arc<SaTokenDao>,
    token_repo: Arc<TokenRepo>,
    session_repo: Arc<SessionRepo>,
    config: Arc<SaTokenConfig>,
    event_bus: SaTokenEventBus,
    online_manager: Option<Arc<OnlineManager>>,
    /// Optional cross-service session; None keeps current login behaviour.
    /// 可选跨服务会话；None 时登录行为与现在一致。
    distributed: Option<Arc<DistributedSessionManager>>,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthService { .. }")
    }
}

impl AuthService {
    /// 构造服务。
    pub fn new(
        dao: Arc<SaTokenDao>,
        config: Arc<SaTokenConfig>,
        token_repo: Arc<TokenRepo>,
        session_repo: Arc<SessionRepo>,
        event_bus: SaTokenEventBus,
        online_manager: Option<Arc<OnlineManager>>,
        distributed: Option<Arc<DistributedSessionManager>>,
    ) -> Self {
        Self {
            dao,
            token_repo,
            session_repo,
            config,
            event_bus,
            online_manager,
            distributed,
        }
    }

    /// Token 仓储 | Token repository
    pub fn token_repo(&self) -> &Arc<TokenRepo> {
        &self.token_repo
    }

    /// Session 仓储 | Session repository
    pub fn session_repo(&self) -> &Arc<SessionRepo> {
        &self.session_repo
    }

    /// 账号命名空间构造（统一校验入口）| Build the account namespace with validation
    fn account_ns(login_type: &str, login_id: &str) -> SaTokenResult<AccountNs> {
        let id =
            LoginId::try_new(login_id).map_err(|e| SaTokenError::ConfigError(e.to_string()))?;
        Ok(SaKeys::account_ns(login_type, &id))
    }

    /// 登录主流程：阶段化写入 + 逆序补偿 + CAS 提交点。
    pub async fn login(&self, req: LoginRequest) -> SaTokenResult<TokenValue> {
        let login_type = req.effective_login_type().to_string();
        let login_id = req.login_id.clone();
        let ns = Self::account_ns(&login_type, &login_id)?;

        let mut compensator = LoginCompensator::new();

        if self.config.enable_nonce
            && let Some(ref nonce_str) = req.nonce
        {
            self.consume_nonce(nonce_str, &login_id, &mut compensator)
                .await?;
        }

        if self.config.is_share
            && let Some(existing) = self
                .token_repo
                .get_login_mapping(&login_type, &login_id)
                .await?
        {
            let existing_token = TokenValue::new(existing);
            if self
                .token_repo
                .load_valid_token_info(&existing_token)
                .await
                .is_ok()
            {
                compensator.commit();
                if self.config.is_log {
                    tracing::info!(login_id = %login_id, "login success");
                }
                return Ok(existing_token);
            }
        }

        let mut token_info = self.build_token_info(&req, &login_type).await?;
        let token = token_info.token.clone();

        let mapping_before = self
            .token_repo
            .get_login_mapping(&login_type, &login_id)
            .await?;

        if !self.config.is_concurrent {
            match self
                .handle_replaced_on_login(&login_type, &login_id, &ns, &req, token.as_str())
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    let _ = compensator.rollback(&self.dao).await;
                    return Err(e);
                }
            }
        }

        let refresh_mgr = if self.config.enable_refresh_token {
            Some(RefreshTokenManager::new(
                self.dao.clone(),
                self.token_repo.clone(),
                self.config.clone(),
            ))
        } else {
            None
        };
        if let Some(ref mgr) = refresh_mgr {
            token_info.refresh_token = Some(mgr.generate(&login_id));
            if self.config.refresh_token_timeout > 0 {
                token_info.refresh_token_expire_time =
                    Some(Utc::now() + ChronoDuration::seconds(self.config.refresh_token_timeout));
            }
        }

        let write_result = self
            .write_login_stages(
                &login_type,
                &login_id,
                &ns,
                &req,
                &token_info,
                mapping_before.as_deref(),
                refresh_mgr.as_ref(),
                &mut compensator,
            )
            .await;

        if let Err(e) = write_result {
            let _ = compensator.rollback(&self.dao).await;
            return Err(e);
        }

        if let Err(e) = self.enforce_max_login_count(&login_type, &login_id).await {
            tracing::warn!(
                login_id = %login_id,
                error = %e,
                "max_login_count enforcement failed after commit, login still succeeds"
            );
        }

        compensator.commit();

        if let Some(dm) = &self.distributed {
            if let Err(e) = dm
                .create_session(login_id.clone(), token.as_str().to_string())
                .await
            {
                tracing::warn!(error = %e, login_id = %login_id, "distributed session create failed after login commit");
            }
        }

        let event =
            SaTokenEvent::login(login_id.clone(), token.as_str()).with_login_type(&login_type);
        self.event_bus.publish(event).await;

        if self.config.is_log {
            tracing::info!(login_id = %login_id, "login success");
        }

        Ok(token)
    }

    async fn consume_nonce(
        &self,
        nonce_str: &str,
        login_id: &str,
        compensator: &mut LoginCompensator,
    ) -> SaTokenResult<()> {
        let nonce_timeout = if self.config.nonce_timeout > 0 {
            self.config.nonce_timeout
        } else {
            self.config.timeout
        };

        let nonce_key = self.dao.keys().nonce(nonce_str);
        let snapshot = self.dao.get_string(&nonce_key).await?;

        let nonce_mgr = NonceManager::from_dao(self.dao.clone(), nonce_timeout);
        nonce_mgr.validate_and_consume(nonce_str, login_id).await?;

        if let Some(raw) = snapshot {
            let ttl = if nonce_timeout > 0 {
                Some(std::time::Duration::from_secs(nonce_timeout as u64))
            } else {
                None
            };
            compensator.on_fail_restore(nonce_key, raw, ttl);
        }

        Ok(())
    }

    async fn build_token_info(
        &self,
        req: &LoginRequest,
        login_type: &str,
    ) -> SaTokenResult<TokenInfo> {
        let token = match req.preset_token.as_deref() {
            Some(preset) if !preset.is_empty() => TokenValue::new(preset),
            _ => {
                let extra = req.extra_data.clone();
                let login_id = req.login_id.clone();
                let cfg = self.config.clone();
                crate::token::generate_unique(
                    cfg.max_try_times,
                    || match extra.as_ref() {
                        Some(extra) => {
                            TokenGenerator::generate_with_login_id_and_extra(&cfg, &login_id, extra)
                        }
                        None => TokenGenerator::generate_with_login_id(&cfg, &login_id),
                    },
                    |t| {
                        let repo = self.token_repo.clone();
                        let token = t.to_string();
                        async move { Ok(repo.get_token_info(&token).await?.is_some()) }
                    },
                )
                .await?
            }
        };

        let mut info = TokenInfo::new(token, req.login_id.as_str());
        info.login_type = crate::token::intern_login_type(login_type);
        info.device = req.device.clone();
        info.extra_data = req.extra_data.clone();
        info.nonce = req.nonce.clone();
        info.update_active_time();

        if let Some(expire) = req.expire_time {
            info.expire_time = Some(expire);
        } else if let Some(timeout) = self.config.timeout_duration() {
            let d = ChronoDuration::from_std(timeout).map_err(|_| {
                SaTokenError::ConfigError("timeout value is out of supported range".to_string())
            })?;
            info.expire_time = Some(Utc::now() + d);
        }

        Ok(info)
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_login_stages(
        &self,
        login_type: &str,
        login_id: &str,
        ns: &AccountNs,
        req: &LoginRequest,
        token_info: &TokenInfo,
        mapping_before: Option<&str>,
        refresh_mgr: Option<&RefreshTokenManager>,
        compensator: &mut LoginCompensator,
    ) -> SaTokenResult<()> {
        let token = token_info.token.as_str();
        let keys = self.dao.keys();

        self.token_repo
            .append_index(login_type, login_id, token)
            .await?;
        compensator.on_fail_list_remove(keys.login_token_index(login_type, login_id), token);

        let session_key = keys
            .session_by_ns(ns)
            .map_err(|e| SaTokenError::ConfigError(e.to_string()))?;
        match self.session_repo.snapshot_account_session(ns).await? {
            Some(old_raw) => {
                compensator.on_fail_restore(session_key, old_raw, self.dao.default_ttl())
            }
            None => compensator.on_fail_delete(session_key),
        }
        let mut terminal = SaTerminalInfo::new(token, req.effective_device().unwrap_or(""));
        if let Some(extra) = req.extra_data.clone() {
            terminal = terminal.with_extra_data(extra);
        }
        self.session_repo.add_terminal(ns, terminal).await?;

        self.token_repo
            .save_token_id_mapping(token, login_type, login_id)
            .await?;
        compensator.on_fail_delete(keys.token_id_mapping(token));

        self.token_repo.save_token_info(token_info).await?;
        compensator.on_fail_delete(keys.token_info(token));

        if self.config.right_now_create_token_session {
            self.session_repo
                .create_token_session(&token_info.token)
                .await?;
            compensator.on_fail_delete(keys.token_session(token));
        }

        if let Some(mgr) = refresh_mgr
            && let Some(ref rt) = token_info.refresh_token
        {
            mgr.store_with_extra(
                rt,
                token,
                login_type,
                login_id,
                token_info.extra_data.as_ref(),
            )
            .await?;
            compensator.on_fail_delete(keys.refresh(rt));
        }

        self.commit_login_mapping(login_type, login_id, token, mapping_before, compensator)
            .await
    }

    async fn commit_login_mapping(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
        mapping_before: Option<&str>,
        compensator: &mut LoginCompensator,
    ) -> SaTokenResult<()> {
        let key = self.dao.keys().login_token(login_type, login_id);

        if self.config.is_concurrent {
            self.token_repo
                .save_login_mapping(login_type, login_id, token)
                .await?;
        } else {
            let swapped = self
                .token_repo
                .cas_login_mapping(login_type, login_id, mapping_before, token)
                .await?;
            if !swapped {
                let swapped_absent = self
                    .token_repo
                    .cas_login_mapping(login_type, login_id, None, token)
                    .await?;
                if !swapped_absent {
                    tracing::warn!(
                        login_id = %login_id,
                        login_type = %login_type,
                        "concurrent login detected on commit point, rolling back this attempt"
                    );
                    return Err(SaTokenError::AccountReplaced);
                }
            }
        }

        compensator.on_fail_delete(key);
        Ok(())
    }

    async fn handle_replaced_on_login(
        &self,
        login_type: &str,
        login_id: &str,
        ns: &AccountNs,
        req: &LoginRequest,
        new_token: &str,
    ) -> SaTokenResult<()> {
        let device = req.effective_device();
        let effective_range = match (self.config.replaced_range, device) {
            (ReplacedRange::CurrDeviceType, None) => {
                tracing::debug!(
                    login_id = %login_id,
                    "device type absent, replaced_range degraded to AllDeviceType"
                );
                ReplacedRange::AllDeviceType
            }
            (range, _) => range,
        };

        let mut targets: HashSet<String> = HashSet::new();

        match effective_range {
            ReplacedRange::CurrDeviceType => {
                for t in self.session_repo.get_terminal_list(ns, device).await? {
                    targets.insert(t.token_value);
                }
            }
            ReplacedRange::AllDeviceType => {
                for t in self.token_repo.list_tokens(login_type, login_id).await? {
                    targets.insert(t);
                }
            }
        }

        if let Some(old) = self
            .token_repo
            .get_login_mapping(login_type, login_id)
            .await?
        {
            targets.insert(old);
        }

        targets.remove(new_token);

        if targets.is_empty() {
            return Ok(());
        }

        match self.config.replaced_login_exit_mode {
            ReplacedLoginExitMode::NewDevice => Err(SaTokenError::AccountReplaced),
            ReplacedLoginExitMode::OldDevice => {
                for t in targets {
                    if let Err(e) = self.logout_replaced(&TokenValue::new(t.clone())).await {
                        tracing::warn!(token = %t, error = %e, "replace of stale token failed");
                    }
                }
                Ok(())
            }
        }
    }

    /// 登出（LOGOUT 模式）| Logout
    pub async fn logout(&self, token: &TokenValue, keep_token_session: bool) -> SaTokenResult<()> {
        let result = match self.config.logout_range {
            LogoutRange::Token => {
                self.logout_internal(token, LogoutMode::Logout, keep_token_session)
                    .await
            }
            LogoutRange::Account => match self.resolve_logout_identity(token.as_str()).await? {
                Some(id) => self.logout_by_login_id(&id.login_type, &id.login_id).await,
                None => {
                    self.logout_internal(token, LogoutMode::Logout, keep_token_session)
                        .await
                }
            },
        };
        if result.is_ok() && self.config.is_log {
            tracing::info!(token = %token.as_str(), "logout success");
        }
        result
    }

    /// 踢下线（KICKOUT 模式，标记 -5）| Kick out, marker `-5`
    pub async fn kick_out_by_token(
        &self,
        token: &TokenValue,
        keep_token_session: bool,
    ) -> SaTokenResult<()> {
        self.logout_internal(token, LogoutMode::KickOut, keep_token_session)
            .await
    }

    /// 顶下线（REPLACED 模式，标记 -4）| Replace, marker `-4`
    pub async fn logout_replaced(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.logout_internal(
            token,
            LogoutMode::Replaced,
            self.config.is_logout_keep_token_session,
        )
        .await
    }

    async fn resolve_logout_identity(&self, token: &str) -> SaTokenResult<Option<LogoutIdentity>> {
        if let Some(info) = self.token_repo.get_token_info(token).await? {
            return Ok(Some(LogoutIdentity {
                login_type: info.login_type.to_string(),
                login_id: info.login_id.to_string(),
                _body_existed: true,
            }));
        }

        match self.token_repo.get_token_id_mapping(token).await? {
            Some(TokenIdMapping::Identity {
                login_type,
                login_id,
            }) => Ok(Some(LogoutIdentity {
                login_type,
                login_id,
                _body_existed: false,
            })),
            _ => Ok(None),
        }
    }

    async fn logout_internal(
        &self,
        token: &TokenValue,
        mode: LogoutMode,
        keep_token_session: bool,
    ) -> SaTokenResult<()> {
        let token_str = token.as_str();
        tracing::debug!(mode = ?mode, token = %token_str, "logout_internal");

        let identity = self.resolve_logout_identity(token_str).await?;

        self.token_repo.delete_token_info(token_str).await?;

        if !keep_token_session {
            let _ = self.session_repo.delete_token_session(token).await;
        }

        match mode {
            LogoutMode::Logout => self.token_repo.delete_token_id_mapping(token_str).await?,
            LogoutMode::KickOut => {
                self.token_repo
                    .mark_token_id(token_str, self.token_repo.kick_out_marker())
                    .await?
            }
            LogoutMode::Replaced => {
                self.token_repo
                    .mark_token_id(token_str, self.token_repo.replaced_marker())
                    .await?
            }
        }

        let Some(identity) = identity else {
            tracing::debug!(token = %token_str, "logout target has no resolvable identity, skipping account-level cleanup");
            return Ok(());
        };

        let lt = identity.login_type.as_str();
        let lid = identity.login_id.as_str();

        if let Err(e) = self.token_repo.remove_index(lt, lid, token_str).await {
            tracing::warn!(token = %token_str, error = %e, "failed to remove token from login index");
        }

        if let Ok(ns) = Self::account_ns(lt, lid) {
            let removed = self
                .session_repo
                .remove_terminal(&ns, token_str)
                .await
                .unwrap_or(false);

            if removed {
                let count = self.session_repo.terminal_count(&ns).await.unwrap_or(0);
                if count == 0 && mode != LogoutMode::Replaced {
                    let _ = self.session_repo.delete_by_ns(&ns).await;
                }
            }
        }

        if mode == LogoutMode::Logout {
            let _ = self
                .token_repo
                .cas_delete_login_mapping(lt, lid, token_str)
                .await;
        }

        if let Some(dm) = &self.distributed {
            if let Err(e) = dm.delete_sessions_by_token(lid, token_str).await {
                tracing::warn!(error = %e, "distributed session delete failed on logout");
            }
        }

        if let Some(online) = &self.online_manager {
            if let Err(e) = online.mark_offline_with_type(lt, lid, token_str).await {
                tracing::warn!(error = %e, "failed to clear online presence on logout");
            }
        }

        let event = match mode {
            LogoutMode::Logout => SaTokenEvent::logout(lid, token_str),
            LogoutMode::KickOut => SaTokenEvent::kick_out(lid, token_str),
            LogoutMode::Replaced => SaTokenEvent::replaced(lid, token_str),
        };
        self.event_bus.publish(event.with_login_type(lt)).await;

        Ok(())
    }

    async fn collect_account_tokens(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<String>> {
        let (alive, pruned) = self.token_repo.prune_index(login_type, login_id).await?;
        if pruned > 0 {
            tracing::debug!(pruned, login_id = %login_id, "pruned orphan index entries");
        }
        if !alive.is_empty() {
            return Ok(alive);
        }

        let mut result = Vec::new();
        let keys = self.dao.keys();
        let pattern = keys.token_scan_pattern(Some(login_type));
        let mut cursor = 0u64;

        loop {
            let page = match self.dao.scan(&pattern, cursor, 100).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(error = %e, "scan fallback unavailable");
                    break;
                }
            };

            for key in &page.keys {
                let Some(token) = keys.parse_token_from_key(key, Some(login_type)) else {
                    continue;
                };
                if let Ok(Some(info)) = self.token_repo.get_token_info(token).await
                    && info.login_id.as_ref() == login_id
                    && info.login_type.as_ref() == login_type
                {
                    result.push(token.to_string());
                }
            }

            if page.next_cursor == 0 {
                break;
            }
            cursor = page.next_cursor;
        }

        if result.is_empty()
            && let Some(one) = self
                .token_repo
                .get_login_mapping(login_type, login_id)
                .await?
        {
            result.push(one);
        }

        Ok(result)
    }

    /// 按账号登出全部 token（LOGOUT 模式）。
    ///
    /// Always uses per-token [`logout_internal`] so `logout_range=Account` cannot recurse.
    /// 始终按单 token 调用 [`logout_internal`]，避免 `logout_range=Account` 时递归。
    pub async fn logout_by_login_id(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        let tokens = self.collect_account_tokens(login_type, login_id).await?;
        let keep = self.config.is_logout_keep_token_session;
        for t in tokens {
            if let Err(e) = self
                .logout_internal(&TokenValue::new(t.clone()), LogoutMode::Logout, keep)
                .await
            {
                tracing::warn!(token = %t, error = %e, "logout of one token failed during account logout");
            }
        }
        Ok(())
    }

    /// 按账号踢下线全部 token（KICKOUT 模式）。
    pub async fn kick_out(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        if let Some(online) = &self.online_manager {
            let _ = online
                .mark_offline_all_with_type(login_type, login_id)
                .await;
            let _ = online
                .kick_out_notify(login_id, "Account kicked out".to_string())
                .await;
        }

        let tokens = self.collect_account_tokens(login_type, login_id).await?;
        for t in tokens {
            if let Err(e) = self
                .kick_out_by_token(
                    &TokenValue::new(t.clone()),
                    self.config.is_logout_keep_token_session,
                )
                .await
            {
                tracing::warn!(token = %t, error = %e, "kickout of one token failed");
            }
        }

        if let Ok(ns) = Self::account_ns(login_type, login_id) {
            let _ = self.session_repo.delete_by_ns(&ns).await;
        }
        Ok(())
    }

    /// 读取并校验 token（按策略自动续签）。
    pub async fn get_token_info(&self, token: &TokenValue) -> SaTokenResult<TokenInfo> {
        match self.token_repo.load_valid_token_info(token).await {
            Ok(info) => Ok(info),
            Err(SaTokenError::TokenExpired) => {
                let _ = self
                    .logout(token, self.config.is_logout_keep_token_session)
                    .await;
                Err(SaTokenError::TokenExpired)
            }
            Err(other) => Err(other),
        }
    }

    /// token 是否有效 | Whether the token is valid
    pub async fn is_valid(&self, token: &TokenValue) -> bool {
        self.get_token_info(token).await.is_ok()
    }

    /// 手动续期到指定秒数（修 B1-29：只写一次存储）。
    pub async fn renew_timeout(
        &self,
        token: &TokenValue,
        timeout_seconds: i64,
    ) -> SaTokenResult<()> {
        let mut info = self.token_repo.load_token_info_no_renew(token).await?;

        info.update_active_time();
        let ttl = if timeout_seconds > 0 {
            info.expire_time = Some(Utc::now() + ChronoDuration::seconds(timeout_seconds));
            Some(std::time::Duration::from_secs(timeout_seconds as u64))
        } else {
            info.expire_time = None;
            None
        };

        let key = self.dao.keys().token_info(token.as_str());
        self.dao.set_object(&key, &info, ttl).await?;

        let event =
            SaTokenEvent::renew_timeout(info.login_id.as_ref(), token.as_str(), timeout_seconds)
                .with_login_type(info.login_type.as_ref());
        self.event_bus.publish(event).await;

        Ok(())
    }

    async fn enforce_max_login_count(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        if self.config.max_login_count <= 0 || !self.config.is_concurrent {
            return Ok(());
        }

        let (alive, pruned) = self.token_repo.prune_index(login_type, login_id).await?;
        if pruned > 0 {
            tracing::debug!(
                pruned,
                login_id = %login_id,
                "pruned orphan tokens before enforcing max_login_count"
            );
        }

        let max = self.config.max_login_count as usize;
        if alive.len() <= max {
            return Ok(());
        }
        let overflow = alive.len() - max;

        for stale in alive.iter().take(overflow) {
            let _ = self
                .token_repo
                .remove_index(login_type, login_id, stale)
                .await;

            let token = TokenValue::new(stale.clone());
            let keep = self.config.is_logout_keep_token_session;
            let outcome = match self.config.overflow_logout_mode {
                LogoutMode::Logout => self.logout(&token, keep).await,
                LogoutMode::KickOut => self.kick_out_by_token(&token, keep).await,
                LogoutMode::Replaced => self.logout_replaced(&token).await,
            };
            if let Err(e) = outcome {
                tracing::warn!(token = %stale, error = %e, "overflow eviction failed");
            }
        }

        Ok(())
    }
}
