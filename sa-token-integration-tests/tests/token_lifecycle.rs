//! P0: Token lifecycle integration tests.
//!
//! Covers token generation (all 9 styles), validation, expiry,
//! auto_renew, active_timeout, and error paths.

mod common;

use common::setup;
use sa_token_core::{SaTokenConfig, SaTokenError, config::TokenStyle, token::TokenValue};

// ── Success cases: token generation styles ─────────────────────────────────

#[tokio::test]
async fn test_uuid_token_is_not_empty() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Uuid)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_1").await.expect("login");
    assert!(!token.as_str().is_empty());
    // UUID has hyphens
    assert!(token.as_str().contains('-'), "UUID should contain hyphens");
}

#[tokio::test]
async fn test_simple_uuid_no_hyphens() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::SimpleUuid)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_1").await.expect("login");
    assert!(
        !token.as_str().contains('-'),
        "SimpleUuid should NOT contain hyphens"
    );
}

#[tokio::test]
async fn test_random_32_length() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Random32)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_1").await.expect("login");
    assert_eq!(token.as_str().len(), 32);
}

#[tokio::test]
async fn test_random_64_length() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Random64)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_1").await.expect("login");
    assert_eq!(token.as_str().len(), 64);
}

#[tokio::test]
async fn test_random_128_length() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Random128)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_1").await.expect("login");
    // 当前实现基于 SHA-512（128 个十六进制字符），Random128 即取满 128 字符。
    assert_eq!(token.as_str().len(), 128);
    assert!(!token.as_str().is_empty());
}

#[tokio::test]
async fn test_hash_style_is_hex() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Hash)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_1").await.expect("login");
    // SHA-256 hex is 64 characters
    assert_eq!(token.as_str().len(), 64);
    // All hex characters
    assert!(token.as_str().chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn test_timestamp_style_format() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Timestamp)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_1").await.expect("login");
    // Format: timestamp_ms_16hex
    assert!(
        token.as_str().contains('_'),
        "Timestamp style should contain underscore"
    );
}

#[tokio::test]
async fn test_tik_style_short() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Tik)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_1").await.expect("login");
    assert_eq!(token.as_str().len(), 8, "Tik token should be 8 characters");
    // All alphanumeric
    assert!(token.as_str().chars().all(|c| c.is_ascii_alphanumeric()));
}

// ── Success cases: token lifecycle ────────────────────────────────────────

#[tokio::test]
async fn test_token_expires_after_timeout() {
    let mgr = setup::fresh_manager_with_config(setup::short_timeout_config(1));
    let token = mgr.login("user_ephemeral").await.expect("login");
    assert!(mgr.is_valid(&token).await);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(
        !mgr.is_valid(&token).await,
        "token should have expired after 3s (1s timeout)"
    );
}

#[tokio::test]
async fn test_auto_renew_extends_token() {
    let config = SaTokenConfig::builder()
        .timeout(3)
        .active_timeout(2)
        .auto_renew(true)
        .token_style(TokenStyle::Uuid)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_renew").await.expect("login");
    // Access token to trigger auto-renew (get_token_info triggers it)
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let _info = mgr
        .get_token_info(&token)
        .await
        .expect("should still be valid");
    // Token should have been renewed, still valid
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_get_token_info_returns_device_and_type() {
    let mgr = setup::fresh_manager();
    let token = mgr
        .login_with_options(
            "user_42",
            Some("vip".into()),
            Some("desktop".into()),
            None,
            None,
            None,
        )
        .await
        .expect("login");
    let info = mgr.get_token_info(&token).await.expect("token info");
    assert_eq!(info.login_id, "user_42");
    assert_eq!(info.login_type, "vip");
    assert_eq!(info.device.as_deref(), Some("desktop"));
}

#[tokio::test]
async fn test_token_info_has_create_time() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_1").await.expect("login");
    let info = mgr.get_token_info(&token).await.expect("token info");
    // create_time should be very close to now
    let now = chrono::Utc::now();
    let diff = (now - info.create_time).num_seconds().abs();
    assert!(diff < 5, "create_time should be within 5 seconds of now");
}

#[tokio::test]
async fn test_timeout_negative_never_expires() {
    let config = SaTokenConfig::builder()
        .timeout(-1) // never expires
        .token_style(TokenStyle::Uuid)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_forever").await.expect("login");
    let info = mgr.get_token_info(&token).await.expect("token info");
    assert!(
        info.expire_time.is_none(),
        "expire_time should be None when timeout=-1"
    );
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_is_valid_empty_token_false() {
    let mgr = setup::fresh_manager();
    let empty = TokenValue::new("");
    assert!(!mgr.is_valid(&empty).await);
}

#[tokio::test]
async fn test_is_valid_random_string_false() {
    let mgr = setup::fresh_manager();
    let random = TokenValue::new("this_is_not_a_valid_token_and_long_enough");
    assert!(!mgr.is_valid(&random).await);
}

#[tokio::test]
async fn test_get_token_info_nonexistent() {
    let mgr = setup::fresh_manager();
    let fake = TokenValue::new("fake_token_0123456789abcdef_long_enough");
    let result = mgr.get_token_info(&fake).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SaTokenError::TokenNotFound));
}

#[tokio::test]
async fn test_get_token_info_expired() {
    let mgr = setup::fresh_manager_with_config(setup::short_timeout_config(1));
    let token = mgr.login("user_exp").await.expect("login");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let result = mgr.get_token_info(&token).await;
    assert!(
        result.is_err(),
        "expired token should return error, got {:?}",
        result
    );
}

#[tokio::test]
async fn test_auto_renew_disabled_does_not_renew() {
    let config = SaTokenConfig::builder()
        .timeout(2)
        .auto_renew(false)
        .token_style(TokenStyle::Uuid)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_no_renew").await.expect("login");
    // Access token info (but auto_renew is off)
    let _ = mgr.get_token_info(&token).await;
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    // Token should have expired despite access
    assert!(!mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_token_value_display() {
    let tv = TokenValue::new("hello_token");
    assert_eq!(tv.as_str(), "hello_token");
    assert_eq!(format!("{}", tv), "hello_token");
}
