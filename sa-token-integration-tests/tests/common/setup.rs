// 本文件是集成测试二进制共享的 helper 模块（每个 tests/*.rs 都 `mod common;`）。
//! 测试基建：隔离 login_id、灰盒拨钟、三态断言、错误变体匹配。
//!
//! 纪律（假绿禁令）：
//! - 禁止 `let _ = some_result.await` 丢弃 Result
//! - 失败路径禁止 unwrap；用 `assert_err` / `expect_err` + 具体 `SaTokenError`
//! - 过期/冻结禁止 `sleep`；用 `expire_token` / `freeze_active` 回写字段
//! - Arrange 可用 `expect("fixture")`；Assert 成功后必须查业务字段
//
// 单个测试二进制只会用到其中一部分函数，Rust 会对未用到的报 dead_code；
// 多二进制各报一次导致噪音，故在模块级统一豁免。
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use chrono::{Duration, Utc};
use sa_token_core::token::{TokenInfo, TokenValue};
use sa_token_core::{
    SaTokenConfig, SaTokenError, SaTokenManager, SaTokenResult, StpUtil, config::TokenStyle,
};
use sa_token_storage_memory::MemoryStorage;

/// Create a default in-memory storage for tests.
pub fn memory_storage() -> Arc<MemoryStorage> {
    Arc::new(MemoryStorage::new())
}

/// Build a default config for tests (UUID tokens, 3600s timeout, concurrent login).
pub fn default_config() -> SaTokenConfig {
    SaTokenConfig::builder()
        .timeout(3600)
        .token_style(TokenStyle::Uuid)
        .is_concurrent(true)
        .build_config()
}

/// Build a config with `is_concurrent = false` (single-session mode).
pub fn non_concurrent_config() -> SaTokenConfig {
    SaTokenConfig::builder()
        .timeout(3600)
        .token_style(TokenStyle::Uuid)
        .is_concurrent(false)
        .is_share(true)
        .build_config()
}

/// Build a config with `is_share = false`.
pub fn non_share_config() -> SaTokenConfig {
    SaTokenConfig::builder()
        .timeout(3600)
        .token_style(TokenStyle::Uuid)
        .is_concurrent(true)
        .is_share(false)
        .build_config()
}

/// Build a config for JWT testing.
pub fn jwt_config(secret: &str) -> SaTokenConfig {
    SaTokenConfig::builder()
        .token_style(TokenStyle::Jwt)
        .jwt_secret_key(secret)
        .timeout(3600)
        .build_config()
}

/// Build a config with a short timeout (in seconds).
pub fn short_timeout_config(timeout_secs: i64) -> SaTokenConfig {
    SaTokenConfig::builder()
        .timeout(timeout_secs)
        .token_style(TokenStyle::Uuid)
        .build_config()
}

/// Build a config with auto_renew enabled（默认 renew_threshold=300，新 token 不会续期）。
pub fn auto_renew_config() -> SaTokenConfig {
    SaTokenConfig::builder()
        .timeout(3600)
        .active_timeout(1800)
        .auto_renew(true)
        .token_style(TokenStyle::Uuid)
        .build_config()
}

/// Shared manager instance across all integration tests.
///
/// Uses `OnceLock` so it is initialized only once per test binary
/// (each `tests/*.rs` is its own binary, so this is per-test-file).
fn shared_manager_cell() -> &'static OnceLock<Arc<SaTokenManager>> {
    static M: OnceLock<Arc<SaTokenManager>> = OnceLock::new();
    &M
}

/// Get or create the shared manager. Uses default config + memory storage.
pub fn shared_manager() -> Arc<SaTokenManager> {
    shared_manager_cell()
        .get_or_init(|| {
            let storage = memory_storage();
            let config = default_config();
            let manager = SaTokenManager::new(storage, config);
            // try_init 可能已被其它路径初始化；忽略「已初始化」错误，不丢业务 Result
            let _init = StpUtil::try_init_manager(manager.clone());
            Arc::new(manager)
        })
        .clone()
}

/// Create a **fresh** manager with the given config + memory storage.
///
/// Does NOT initialize `StpUtil` — use `shared_manager()` if you need `StpUtil`.
/// Use this when test isolation matters (different configs, separate storage).
pub fn fresh_manager_with_config(config: SaTokenConfig) -> Arc<SaTokenManager> {
    let storage = memory_storage();
    Arc::new(SaTokenManager::new(storage, config))
}

/// Create a **fresh** manager with default config + memory storage.
pub fn fresh_manager() -> Arc<SaTokenManager> {
    fresh_manager_with_config(default_config())
}

// ── 隔离：唯一 login_id ───────────────────────────────────────────────────

static LOGIN_SEQ: AtomicU64 = AtomicU64::new(1);

/// 生成全局唯一 login_id，避免共享 StpUtil/存储时碰撞。
pub fn unique_login_id(prefix: &str) -> String {
    let n = LOGIN_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{n}")
}

// ── 灰盒拨钟：禁止 sleep ──────────────────────────────────────────────────

/// 把 token 的 expire_time 拨到过去，模拟过期（不 sleep）。
///
/// 直接写存储，绕过 get_token_info 的过期检查，避免拨钟前读失败。
pub async fn expire_token(mgr: &SaTokenManager, token: &TokenValue) {
    let key = mgr.keys().token_info(token.as_str());
    let raw = mgr
        .storage()
        .get(&key)
        .await
        .expect("storage get")
        .expect("token_info must exist before expire_token");
    let mut info: TokenInfo = mgr.config.decode(&raw).expect("decode token_info");
    info.expire_time = Some(Utc::now() - Duration::seconds(10));
    mgr.storage()
        .set(
            &key,
            &mgr.config.encode(&info).expect("encode token_info"),
            None,
        )
        .await
        .expect("storage set expired info");
}

/// 把 last_active_time 拨到 past，触发 active_timeout 冻结（不 sleep）。
pub async fn freeze_active(mgr: &SaTokenManager, token: &TokenValue, idle_secs: i64) {
    let key = mgr.keys().token_info(token.as_str());
    let raw = mgr
        .storage()
        .get(&key)
        .await
        .expect("storage get")
        .expect("token_info must exist before freeze_active");
    let mut info: TokenInfo = mgr.config.decode(&raw).expect("decode token_info");
    info.last_active_time = Utc::now() - Duration::seconds(idle_secs);
    mgr.storage()
        .set(
            &key,
            &mgr.config.encode(&info).expect("encode token_info"),
            mgr.config.timeout_duration(),
        )
        .await
        .expect("storage set frozen info");
}

/// 把 expire_time 拨到「剩余 remaining_secs」，用于触发 renew_threshold 续期。
pub async fn set_token_remaining(mgr: &SaTokenManager, token: &TokenValue, remaining_secs: i64) {
    let key = mgr.keys().token_info(token.as_str());
    let raw = mgr
        .storage()
        .get(&key)
        .await
        .expect("storage get")
        .expect("token_info must exist");
    let mut info: TokenInfo = mgr.config.decode(&raw).expect("decode token_info");
    info.expire_time = Some(Utc::now() + Duration::seconds(remaining_secs));
    mgr.storage()
        .set(
            &key,
            &mgr.config.encode(&info).expect("encode"),
            mgr.config.timeout_duration(),
        )
        .await
        .expect("storage set remaining");
}

// ── 三态断言 ──────────────────────────────────────────────────────────────

/// 断言 token 已登录：is_login + login_id 匹配。
pub async fn assert_logged_in(mgr: &SaTokenManager, token: &TokenValue, login_id: &str) {
    assert!(
        mgr.is_valid(token).await,
        "token should be valid for login_id={login_id}"
    );
    let info = mgr
        .get_token_info(token)
        .await
        .expect("get_token_info after login");
    assert_eq!(info.login_id.as_ref(), login_id);
}

/// 断言 StpUtil 视角已登录。
pub async fn assert_stp_logged_in(token: &TokenValue, login_id: &str) {
    assert!(
        StpUtil::is_login(token).await,
        "StpUtil::is_login should be true for {login_id}"
    );
    let info = StpUtil::get_token_info(token)
        .await
        .expect("StpUtil get_token_info");
    assert_eq!(info.login_id.as_ref(), login_id);
}

/// 失败路径：必须是指定错误变体，禁止只 is_err / unwrap。
pub fn assert_err(result: SaTokenResult<impl std::fmt::Debug>, kind: &str) {
    match (result, kind) {
        (Err(SaTokenError::AccountKickedOut), "kicked") => {}
        (Err(SaTokenError::AccountReplaced), "replaced") => {}
        (Err(SaTokenError::TokenExpired), "expired") => {}
        (Err(SaTokenError::NotLogin), "not_login") => {}
        (Err(SaTokenError::TokenNotFound), "not_found") => {}
        (Err(SaTokenError::TokenInactive), "inactive") => {}
        (Err(SaTokenError::AccountBanned(_)), "banned") => {}
        (Err(SaTokenError::NotSafe(_)), "not_safe") => {}
        (Err(SaTokenError::NonceAlreadyUsed), "nonce_used") => {}
        (Err(SaTokenError::PermissionDeniedDetail(_)), "perm_denied") => {}
        (Err(SaTokenError::InvalidToken(_)), "invalid_token") => {}
        (Err(SaTokenError::RefreshTokenNotFound), "refresh_not_found") => {}
        (other, k) => panic!("expected error kind `{k}`, got {other:?}"),
    }
}
