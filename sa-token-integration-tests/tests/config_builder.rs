//! P1: Config Builder integration tests.

mod common;

use common::setup;
use sa_token_core::{SaTokenConfig, SaTokenListener, config::TokenStyle};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn test_default_config_values() {
    let config = SaTokenConfig::default();
    assert_eq!(config.token_name, "sa-token");
    assert_eq!(config.timeout, 2592000);
    assert_eq!(config.active_timeout, -1);
    assert!(!config.auto_renew);
    assert!(config.is_concurrent);
    assert!(!config.is_share);
    assert!(matches!(config.token_style, TokenStyle::Uuid));
    assert_eq!(config.storage_key_prefix, "sa:");
    assert!(!config.enable_nonce);
    assert!(!config.enable_refresh_token);
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
    assert!(config.auto_renew);
    assert!(matches!(config.token_style, TokenStyle::Jwt));
    assert_eq!(config.jwt_secret_key.as_deref(), Some("my-secret"));
    assert!(config.enable_nonce);
    assert!(config.enable_refresh_token);
}

#[tokio::test]
async fn test_timeout_negative_never_expires_field_and_behavior() {
    let config = SaTokenConfig::builder().timeout(-1).build_config();
    assert_eq!(config.timeout, -1);
    assert!(config.timeout_duration().is_none());
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("forever").await.expect("login");
    let info = mgr.get_token_info(&token).await.expect("info");
    assert!(info.expire_time.is_none());
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_timeout_positive_has_duration() {
    let config = SaTokenConfig::builder().timeout(3600).build_config();
    let dur = config.timeout_duration().expect("duration");
    assert_eq!(dur.as_secs(), 3600);
}

#[tokio::test]
async fn test_all_token_styles_login_valid() {
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
        let mut builder = SaTokenConfig::builder().token_style(*style).timeout(3600);
        if matches!(style, TokenStyle::Jwt) {
            builder = builder.jwt_secret_key("test-secret-for-style");
        }
        let config = builder.build_config();
        assert_eq!(
            std::mem::discriminant(&config.token_style),
            std::mem::discriminant(style)
        );
        let mgr = setup::fresh_manager_with_config(config);
        let token = mgr
            .login(format!("style_{style:?}"))
            .await
            .expect("login for style");
        assert!(
            mgr.is_valid(&token).await,
            "style {style:?} token must be valid"
        );
    }
}

struct CountingListener {
    logins: AtomicUsize,
}

#[async_trait::async_trait]
impl SaTokenListener for CountingListener {
    async fn on_login(&self, _login_id: &str, _token: &str, _login_type: &str) {
        self.logins.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn test_builder_register_listener_fires_on_login() {
    let listener = Arc::new(CountingListener {
        logins: AtomicUsize::new(0),
    });
    let storage = setup::memory_storage();
    let mgr = SaTokenConfig::builder()
        .storage(storage)
        .register_listener(listener.clone())
        .build();
    mgr.login("listener_user").await.expect("login");
    assert_eq!(
        listener.logins.load(Ordering::SeqCst),
        1,
        "listener must receive login event"
    );
}

#[tokio::test]
#[should_panic(expected = "Storage must be set")]
async fn test_build_without_storage_panics() {
    SaTokenConfig::builder().timeout(3600).build();
}

#[tokio::test]
async fn test_jwt_style_without_secret() {
    let err = SaTokenConfig::builder()
        .token_style(TokenStyle::Jwt)
        .timeout(3600)
        .try_build_config()
        .expect_err("jwt without secret should fail");
    assert!(err.to_string().contains("jwt_secret_key"));
}
