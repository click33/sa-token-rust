//! P0: Token lifecycle integration tests.
//!
//! 风格格式、过期拨钟、auto_renew 阈值命中；禁止 sleep 测过期。

mod common;

use common::setup;
use sa_token_core::{SaTokenConfig, SaTokenError, config::TokenStyle, token::TokenValue};

#[tokio::test]
async fn test_uuid_token_format() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Uuid)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_1").await.expect("login");
    assert!(token.as_str().contains('-'));
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_simple_uuid_no_hyphens() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::SimpleUuid)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_1").await.expect("login");
    assert!(!token.as_str().contains('-'));
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_random_32_length() {
    let mgr = setup::fresh_manager_with_config(
        SaTokenConfig::builder()
            .token_style(TokenStyle::Random32)
            .timeout(3600)
            .build_config(),
    );
    let token = mgr.login("user_1").await.expect("login");
    assert_eq!(token.as_str().len(), 32);
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_random_64_length() {
    let mgr = setup::fresh_manager_with_config(
        SaTokenConfig::builder()
            .token_style(TokenStyle::Random64)
            .timeout(3600)
            .build_config(),
    );
    let token = mgr.login("user_1").await.expect("login");
    assert_eq!(token.as_str().len(), 64);
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_random_128_length() {
    let mgr = setup::fresh_manager_with_config(
        SaTokenConfig::builder()
            .token_style(TokenStyle::Random128)
            .timeout(3600)
            .build_config(),
    );
    let token = mgr.login("user_1").await.expect("login");
    assert_eq!(token.as_str().len(), 128);
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_hash_style_is_hex() {
    let mgr = setup::fresh_manager_with_config(
        SaTokenConfig::builder()
            .token_style(TokenStyle::Hash)
            .timeout(3600)
            .build_config(),
    );
    let token = mgr.login("user_1").await.expect("login");
    assert_eq!(token.as_str().len(), 64);
    assert!(token.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_timestamp_style_format() {
    let mgr = setup::fresh_manager_with_config(
        SaTokenConfig::builder()
            .token_style(TokenStyle::Timestamp)
            .timeout(3600)
            .build_config(),
    );
    let token = mgr.login("user_1").await.expect("login");
    assert!(token.as_str().contains('_'));
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_tik_style_short() {
    let mgr = setup::fresh_manager_with_config(
        SaTokenConfig::builder()
            .token_style(TokenStyle::Tik)
            .timeout(3600)
            .build_config(),
    );
    let token = mgr.login("user_1").await.expect("login");
    assert_eq!(token.as_str().len(), 8);
    assert!(token.as_str().chars().all(|c| c.is_ascii_alphanumeric()));
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_token_expires_after_clock_skew() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_ephemeral").await.expect("login");
    assert!(mgr.is_valid(&token).await);
    setup::expire_token(&mgr, &token).await;
    assert!(!mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_auto_renew_extends_expire_time() {
    let config = SaTokenConfig::builder()
        .timeout(3600)
        .active_timeout(1800)
        .auto_renew(true)
        .renew_threshold(300)
        .token_style(TokenStyle::Uuid)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_renew").await.expect("login");
    let before = mgr
        .get_token_info(&token)
        .await
        .expect("info")
        .expire_time
        .expect("has expire");
    // 拨到阈值内（remaining=200 <= 300），访问应续期
    setup::set_token_remaining(&mgr, &token, 200).await;
    let after = mgr
        .get_token_info(&token)
        .await
        .expect("renew should keep valid");
    let after_exp = after.expire_time.expect("expire after renew");
    assert!(
        after_exp > before - chrono::Duration::hours(1) + chrono::Duration::minutes(30)
            || after_exp > chrono::Utc::now() + chrono::Duration::seconds(1000),
        "expire_time should be extended after renew, before={before:?} after={after_exp:?}"
    );
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_auto_renew_disabled_does_not_renew() {
    let config = SaTokenConfig::builder()
        .timeout(3600)
        .auto_renew(false)
        .token_style(TokenStyle::Uuid)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_no_renew").await.expect("login");
    let before = mgr
        .get_token_info(&token)
        .await
        .expect("info")
        .expire_time
        .expect("exp");
    setup::set_token_remaining(&mgr, &token, 200).await;
    let mid = mgr.get_token_info(&token).await.expect("access");
    // auto_renew=false：remaining 拨小后访问不得拉回大 timeout
    let mid_exp = mid.expire_time.expect("exp");
    assert!(
        (mid_exp - chrono::Utc::now()).num_seconds() < 300,
        "without auto_renew, expire should stay near remaining=200"
    );
    setup::expire_token(&mgr, &token).await;
    assert!(!mgr.is_valid(&token).await);
    let _ = before; // 保留对照意图
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
    let info = mgr.get_token_info(&token).await.expect("info");
    assert_eq!(info.login_id.as_ref(), "user_42");
    assert_eq!(info.login_type.as_ref(), "vip");
    assert_eq!(info.device.as_deref(), Some("desktop"));
}

#[tokio::test]
async fn test_timeout_negative_never_expires_behavior() {
    let config = SaTokenConfig::builder()
        .timeout(-1)
        .token_style(TokenStyle::Uuid)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_forever").await.expect("login");
    let info = mgr.get_token_info(&token).await.expect("info");
    assert!(info.expire_time.is_none());
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_is_valid_empty_and_random_false() {
    let mgr = setup::fresh_manager();
    assert!(!mgr.is_valid(&TokenValue::new("")).await);
    assert!(
        !mgr.is_valid(&TokenValue::new(
            "this_is_not_a_valid_token_and_long_enough"
        ))
        .await
    );
}

#[tokio::test]
async fn test_get_token_info_nonexistent() {
    let mgr = setup::fresh_manager();
    let fake = TokenValue::new("fake_token_0123456789abcdef_long_enough");
    setup::assert_err(mgr.get_token_info(&fake).await, "not_found");
}

#[tokio::test]
async fn test_get_token_info_expired_via_clock() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_exp").await.expect("login");
    setup::expire_token(&mgr, &token).await;
    let result = mgr.get_token_info(&token).await;
    assert!(
        matches!(
            result,
            Err(SaTokenError::TokenExpired | SaTokenError::TokenNotFound)
        ),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_token_value_display() {
    let tv = TokenValue::new("hello_token");
    assert_eq!(tv.as_str(), "hello_token");
    assert_eq!(format!("{tv}"), "hello_token");
}

#[tokio::test]
async fn test_active_timeout_freeze_via_clock() {
    let config = SaTokenConfig::builder()
        .timeout(3600)
        .active_timeout(60)
        .auto_renew(false)
        .token_style(TokenStyle::Uuid)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_freeze").await.expect("login");
    // 空闲 61s > active_timeout 60 → TokenInactive
    setup::freeze_active(&mgr, &token, 61).await;
    setup::assert_err(mgr.get_token_info(&token).await, "inactive");
}
