// 本文件是 20 个集成测试二进制共享的 helper 模块（每个 tests/*.rs 都 `mod common;`）。
// 单个测试二进制只会用到其中一部分函数，Rust 会对未用到的报 dead_code；
// 20 个二进制各报一次导致 192 条噪音，故在模块级统一豁免。
// 这不是掩盖问题：这些函数全部被至少一个测试使用，只是不被每个二进制使用。
#![allow(dead_code)]

use std::sync::{Arc, OnceLock};

use sa_token_core::{SaTokenConfig, SaTokenManager, StpUtil, config::TokenStyle};
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

/// Build a config with auto_renew enabled.
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
            let _ = StpUtil::try_init_manager(manager.clone());
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
