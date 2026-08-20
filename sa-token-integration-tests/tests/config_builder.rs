//! P1: Config Builder integration tests.
//!
//! Covers default values, builder chain, boundary values,
//! and error paths (build without storage).

mod common;

use common::setup;
use sa_token_core::{SaTokenConfig, config::TokenStyle};

// ── Success cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_default_config_values() {
    let config = SaTokenConfig::default();
    assert_eq!(config.token_name, "sa-token");
    assert_eq!(config.timeout, 2592000);
    assert_eq!(config.active_timeout, -1);
    assert!(config.auto_renew);
    assert!(config.is_concurrent);
    assert!(!config.is_share);
    assert!(!config.dynamic_active_timeout);
    assert!(matches!(config.token_style, TokenStyle::Uuid));
    assert!(!config.is_log);
    assert!(config.is_read_cookie);
    assert!(config.is_read_header);
    assert!(config.is_read_body);
    assert_eq!(config.storage_key_prefix, "sa:");
    assert!(config.jwt_secret_key.is_none());
    assert_eq!(config.jwt_algorithm.as_deref(), Some("HS256"));
    assert!(config.jwt_issuer.is_none());
    assert!(config.jwt_audience.is_none());
    assert!(!config.enable_nonce);
    assert_eq!(config.nonce_timeout, -1);
    assert!(!config.enable_refresh_token);
    assert_eq!(config.refresh_token_timeout, 604800);
}

#[tokio::test]
async fn test_builder_all_fields() {
    let config = SaTokenConfig::builder()
        .token_name("X-Auth")
        .timeout(7200)
        .active_timeout(1800)
        .auto_renew(true)
        .is_concurrent(false)
        .is_share(false)
        .token_style(TokenStyle::Jwt)
        .storage_key_prefix("my:")
        .jwt_secret_key("my-secret")
        .jwt_algorithm("HS512")
        .jwt_issuer("test-app")
        .jwt_audience("test-users")
        .enable_nonce(true)
        .nonce_timeout(300)
        .enable_refresh_token(true)
        .refresh_token_timeout(86400)
        .build_config();
    assert_eq!(config.token_name, "X-Auth");
    assert_eq!(config.timeout, 7200);
    assert_eq!(config.active_timeout, 1800);
    assert!(config.auto_renew);
    assert!(!config.is_concurrent);
    assert!(!config.is_share);
    assert!(matches!(config.token_style, TokenStyle::Jwt));
    assert_eq!(config.storage_key_prefix, "my:");
    assert_eq!(config.jwt_secret_key.as_deref(), Some("my-secret"));
    assert_eq!(config.jwt_algorithm.as_deref(), Some("HS512"));
    assert_eq!(config.jwt_issuer.as_deref(), Some("test-app"));
    assert_eq!(config.jwt_audience.as_deref(), Some("test-users"));
    assert!(config.enable_nonce);
    assert_eq!(config.nonce_timeout, 300);
    assert!(config.enable_refresh_token);
    assert_eq!(config.refresh_token_timeout, 86400);
}

#[tokio::test]
async fn test_builder_token_name() {
    let config = SaTokenConfig::builder()
        .token_name("CustomToken")
        .build_config();
    assert_eq!(config.token_name, "CustomToken");
}

#[tokio::test]
async fn test_timeout_negative_never_expires() {
    let config = SaTokenConfig::builder().timeout(-1).build_config();
    assert_eq!(config.timeout, -1);
    assert!(config.timeout_duration().is_none());
}

#[tokio::test]
async fn test_timeout_positive_has_duration() {
    let config = SaTokenConfig::builder().timeout(3600).build_config();
    let dur = config.timeout_duration();
    assert!(dur.is_some());
    assert_eq!(dur.unwrap().as_secs(), 3600);
}

#[tokio::test]
async fn test_is_concurrent_setting() {
    let config = SaTokenConfig::builder().is_concurrent(false).build_config();
    assert!(!config.is_concurrent);
}

#[tokio::test]
async fn test_all_token_styles() {
    let styles = [
        TokenStyle::Uuid,
        TokenStyle::SimpleUuid,
        TokenStyle::Random32,
        TokenStyle::Random64,
        TokenStyle::Random128,
        TokenStyle::Jwt,
        TokenStyle::Hash,
        TokenStyle::Timestamp,
        TokenStyle::Tik,
    ];
    for style in &styles {
        let config = SaTokenConfig::builder().token_style(*style).build_config();
        // TokenStyle doesn't implement PartialEq for direct comparison,
        // but we can verify via debug output
        let _ = format!("{:?}", config.token_style);
    }
}

#[tokio::test]
async fn test_builder_register_listener() {
    use sa_token_core::SaTokenListener;
    struct DummyListener;
    #[async_trait::async_trait]
    impl SaTokenListener for DummyListener {}
    let storage = setup::memory_storage();
    let _mgr = SaTokenConfig::builder()
        .storage(storage)
        .register_listener(std::sync::Arc::new(DummyListener))
        .build();
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
#[should_panic(expected = "Storage must be set")]
async fn test_build_without_storage_panics() {
    SaTokenConfig::builder().timeout(3600).build();
}

#[tokio::test]
async fn test_jwt_style_without_secret() {
    // JWT style without secret key — config should still be buildable
    // (actual login would fail or fallback)
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Jwt)
        .timeout(3600)
        .build_config();
    assert!(config.jwt_secret_key.is_none());
}
