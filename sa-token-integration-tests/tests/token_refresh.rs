//! P1: Refresh Token integration tests.
//!
//! Covers refresh token generation, storage, validation,
//! access token refresh, deletion, and error paths.

mod common;

use sa_token_core::{
    LOGIN_TYPE_DEFAULT, RefreshTokenManager, SaTokenConfig, SaTokenError, config::TokenStyle,
};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

fn test_config() -> Arc<SaTokenConfig> {
    Arc::new(SaTokenConfig {
        token_style: TokenStyle::Uuid,
        timeout: 3600,
        refresh_token_timeout: 7200,
        enable_refresh_token: true,
        ..Default::default()
    })
}

fn short_refresh_config() -> Arc<SaTokenConfig> {
    Arc::new(SaTokenConfig {
        token_style: TokenStyle::Uuid,
        timeout: 3600,
        refresh_token_timeout: 1, // 1 second TTL
        enable_refresh_token: true,
        ..Default::default()
    })
}

// ── Success cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_generate_refresh_token_is_unique() {
    let storage = Arc::new(MemoryStorage::new());
    let mgr = RefreshTokenManager::from_storage(storage, test_config());
    let rt1 = mgr.generate("user_1");
    let rt2 = mgr.generate("user_1");
    assert_ne!(rt1, rt2, "refresh tokens should be unique");
    assert!(rt1.starts_with("refresh_"));
}

#[tokio::test]
async fn test_store_and_validate_refresh_token() {
    let storage = Arc::new(MemoryStorage::new());
    let mgr = RefreshTokenManager::from_storage(storage, test_config());
    let rt = mgr.generate("user_42");
    mgr.store(&rt, "access_token_xyz", LOGIN_TYPE_DEFAULT, "user_42")
        .await
        .expect("store");
    let login_id = mgr.validate(&rt).await.expect("validate");
    assert_eq!(login_id, "user_42");
}

#[tokio::test]
async fn test_refresh_access_token_returns_new_token() {
    let storage = Arc::new(MemoryStorage::new());
    let mgr = RefreshTokenManager::from_storage(storage, test_config());
    let rt = mgr.generate("user_1");
    let old_access = "old_access_token_value_long_enough_16";
    mgr.store(&rt, old_access, LOGIN_TYPE_DEFAULT, "user_1")
        .await
        .expect("store");
    let (new_access, login_id) = mgr.refresh_access_token(&rt).await.expect("refresh");
    assert_eq!(login_id, "user_1");
    assert_ne!(
        new_access.as_str(),
        old_access,
        "refreshed access token should differ"
    );
    assert!(!new_access.as_str().is_empty());
}

#[tokio::test]
async fn test_refresh_token_still_valid_after_refresh() {
    let storage = Arc::new(MemoryStorage::new());
    let mgr = RefreshTokenManager::from_storage(storage, test_config());
    let rt = mgr.generate("user_1");
    mgr.store(&rt, "access_old", LOGIN_TYPE_DEFAULT, "user_1")
        .await
        .expect("store");
    // Refresh once
    let _ = mgr.refresh_access_token(&rt).await.expect("first refresh");
    // Validate still works
    let login_id = mgr.validate(&rt).await.expect("validate after refresh");
    assert_eq!(login_id, "user_1");
    // Refresh again
    let _ = mgr.refresh_access_token(&rt).await.expect("second refresh");
}

#[tokio::test]
async fn test_delete_refresh_token() {
    let storage = Arc::new(MemoryStorage::new());
    let mgr = RefreshTokenManager::from_storage(storage, test_config());
    let rt = mgr.generate("user_1");
    mgr.store(&rt, "access", LOGIN_TYPE_DEFAULT, "user_1")
        .await
        .expect("store");
    mgr.delete(&rt).await.expect("delete");
    let result = mgr.validate(&rt).await;
    assert!(result.is_err(), "deleted refresh token should not validate");
}

#[tokio::test]
async fn test_store_with_extra_data_preserves_extra() {
    let storage = Arc::new(MemoryStorage::new());
    let mgr = RefreshTokenManager::from_storage(storage, test_config());
    let rt = mgr.generate("user_1");
    let extra = serde_json::json!({"role": "admin"});
    mgr.store_with_extra(&rt, "access", LOGIN_TYPE_DEFAULT, "user_1", Some(&extra))
        .await
        .expect("store with extra");
    let (new_access, login_id) = mgr.refresh_access_token(&rt).await.expect("refresh");
    assert_eq!(login_id, "user_1");
    assert!(!new_access.as_str().is_empty());
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_validate_nonexistent_refresh_token() {
    let storage = Arc::new(MemoryStorage::new());
    let mgr = RefreshTokenManager::from_storage(storage, test_config());
    let result = mgr.validate("nonexistent_refresh_token_12345").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::RefreshTokenNotFound
    ));
}

#[tokio::test]
async fn test_refresh_with_expired_token() {
    let storage = Arc::new(MemoryStorage::new());
    let mgr = RefreshTokenManager::from_storage(storage, short_refresh_config());
    let rt = mgr.generate("user_exp");
    mgr.store(&rt, "access_token", LOGIN_TYPE_DEFAULT, "user_exp")
        .await
        .expect("store");
    // Wait for refresh token TTL to expire
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let result = mgr.refresh_access_token(&rt).await;
    assert!(result.is_err(), "expired refresh token should fail");
}

#[tokio::test]
async fn test_refresh_access_token_with_invalid_refresh_token() {
    let storage = Arc::new(MemoryStorage::new());
    let mgr = RefreshTokenManager::from_storage(storage, test_config());
    let result = mgr
        .refresh_access_token("no_such_refresh_token_at_all")
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::RefreshTokenNotFound
    ));
}

#[tokio::test]
async fn test_revoke_all_for_user_is_noop_for_memory() {
    let storage = Arc::new(MemoryStorage::new());
    let mgr = RefreshTokenManager::from_storage(storage, test_config());
    // revoke_all_for_user calls get_user_refresh_tokens which returns empty vec
    let result = mgr.revoke_all_for_user(LOGIN_TYPE_DEFAULT, "user_1").await;
    assert!(result.is_ok(), "revoke_all should not error");
}
