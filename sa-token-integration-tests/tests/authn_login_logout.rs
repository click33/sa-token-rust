//! P0: Login / Logout / Kick-out / Multi-device integration tests.
//!
//! Covers both success and failure paths for `SaTokenManager` and `StpUtil`
//! authentication lifecycle methods.

mod common;

use common::setup;
use sa_token_core::{SaTokenError, StpUtil, token::TokenValue};

// ── Helper: ensure StpUtil is initialized (once per test binary) ───────────
fn init() {
    let _ = setup::shared_manager();
}

// ── Success cases: manager-based ───────────────────────────────────────────

#[tokio::test]
async fn test_login_creates_token() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_1").await.expect("login should succeed");
    assert!(!token.as_str().is_empty(), "token should not be empty");
}

#[tokio::test]
async fn test_login_then_is_valid_returns_true() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_1").await.expect("login");
    assert!(mgr.is_valid(&token).await, "user should be logged in");
}

#[tokio::test]
async fn test_login_multiple_users_get_different_tokens() {
    let mgr = setup::fresh_manager();
    let t1 = mgr.login("user_a").await.expect("login a");
    let t2 = mgr.login("user_b").await.expect("login b");
    assert_ne!(
        t1.as_str(),
        t2.as_str(),
        "different users → different tokens"
    );
}

#[tokio::test]
async fn test_logout_by_token_then_is_valid_false() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_1").await.expect("login");
    mgr.logout(&token).await.expect("logout");
    assert!(
        !mgr.is_valid(&token).await,
        "should not be valid after logout"
    );
}

#[tokio::test]
async fn test_logout_by_login_id() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_1").await.expect("login");
    mgr.logout_by_login_id("login", "user_1")
        .await
        .expect("logout_by_login_id");
    assert!(
        !mgr.is_valid(&token).await,
        "token should be invalid after logout by login_id"
    );
}

#[tokio::test]
async fn test_kick_out_then_is_login_false() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_1").await.expect("login");
    mgr.kick_out("login", "user_1").await.expect("kick_out");
    assert!(
        !mgr.is_valid(&token).await,
        "kicked-out token should be invalid"
    );
}

#[tokio::test]
async fn test_is_concurrent_multiple_logins_produce_different_tokens() {
    let mgr = setup::fresh_manager(); // is_concurrent = true (default)
    let t1 = mgr.login("user_1").await.expect("first login");
    let t2 = mgr.login("user_1").await.expect("second login");
    assert_ne!(
        t1.as_str(),
        t2.as_str(),
        "concurrent logins → different tokens"
    );
}

#[tokio::test]
async fn test_non_concurrent_mode_kicks_previous_sessions() {
    let config = sa_token_core::SaTokenConfig::builder()
        .timeout(3600)
        .token_style(sa_token_core::config::TokenStyle::Uuid)
        .is_concurrent(false)
        .is_share(false)
        .auto_renew(false)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let t1 = mgr.login("user_1").await.expect("first login");
    assert!(
        mgr.is_valid(&t1).await,
        "first token should be valid after first login"
    );
    let t2 = mgr.login("user_1").await.expect("second login");
    assert!(
        !mgr.is_valid(&t1).await,
        "old token should be invalid after non-concurrent re-login"
    );
    assert!(
        mgr.is_valid(&t2).await,
        "new token should be valid after non-concurrent re-login"
    );
}

#[tokio::test]
async fn test_login_by_device_creates_separate_session() {
    let mgr = setup::fresh_manager();
    let t_web = mgr
        .login_with_options("user_1", None, Some("web".into()), None, None, None)
        .await
        .expect("web login");
    let t_mobile = mgr
        .login_with_options("user_1", None, Some("mobile".into()), None, None, None)
        .await
        .expect("mobile login");
    assert_ne!(
        t_web.as_str(),
        t_mobile.as_str(),
        "different devices → different tokens"
    );
}

#[tokio::test]
async fn test_login_with_options_sets_device() {
    let mgr = setup::fresh_manager();
    let token = mgr
        .login_with_options("user_1", None, Some("iPhone".into()), None, None, None)
        .await
        .expect("login");
    let info = mgr.get_token_info(&token).await.expect("token info");
    assert_eq!(info.device.as_deref(), Some("iPhone"));
}

#[tokio::test]
async fn test_login_with_options_sets_login_type() {
    let mgr = setup::fresh_manager();
    let token = mgr
        .login_with_options("user_1", Some("admin".into()), None, None, None, None)
        .await
        .expect("login");
    let info = mgr.get_token_info(&token).await.expect("token info");
    assert_eq!(info.login_type, "admin");
}

#[tokio::test]
async fn test_login_builder_with_extra_data() {
    let mgr = setup::fresh_manager();
    let extra = serde_json::json!({"ip": "192.168.1.1"});
    let token = mgr
        .login_with_options("user_1", None, None, Some(extra), None, None)
        .await
        .expect("login");
    let info = mgr.get_token_info(&token).await.expect("token info");
    let stored_extra = info.extra_data.expect("extra_data should be set");
    assert_eq!(stored_extra["ip"], "192.168.1.1");
}

#[tokio::test]
async fn test_get_token_info_returns_login_id() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_42").await.expect("login");
    let info = mgr.get_token_info(&token).await.expect("token info");
    assert_eq!(info.login_id, "user_42");
}

#[tokio::test]
async fn test_stp_util_login_with_type_sets_login_type() {
    init();
    let token = StpUtil::login_with_type("user_admin", "admin")
        .await
        .expect("login_with_type");
    let info = StpUtil::get_token_info(&token).await.expect("token info");
    assert_eq!(info.login_type, "admin");
}

#[tokio::test]
async fn test_get_all_tokens_by_login_id_after_concurrent_logins() {
    init();
    let t1 = StpUtil::login("user_multi").await.expect("login 1");
    let t2 = StpUtil::login("user_multi").await.expect("login 2");
    let tokens = StpUtil::get_all_tokens_by_login_id("user_multi")
        .await
        .expect("tokens");
    assert_eq!(tokens.len(), 2);
    assert!(tokens.iter().any(|t| t.as_str() == t1.as_str()));
    assert!(tokens.iter().any(|t| t.as_str() == t2.as_str()));
}

// ── Success cases: StpUtil-based ──────────────────────────────────────────

#[tokio::test]
async fn test_stp_util_login_works() {
    init();
    let token = StpUtil::login("user_stp").await.expect("StpUtil login");
    assert!(!token.as_str().is_empty());
    assert!(StpUtil::is_login(&token).await);
}

#[tokio::test]
async fn test_stp_util_logout_by_token_works() {
    init();
    let token = StpUtil::login("user_stp_2").await.expect("login");
    StpUtil::logout_by_token(&token)
        .await
        .expect("logout_by_token");
    assert!(!StpUtil::is_login(&token).await);
}

#[tokio::test]
async fn test_is_login_by_login_id() {
    init();
    let token = StpUtil::login("user_by_id").await.expect("login");
    assert!(StpUtil::is_login_by_login_id("user_by_id").await);
    StpUtil::login(10001).await.expect("numeric login");
    assert!(StpUtil::is_login_by_login_id(10001).await);
    // Ensure the first token is still valid
    assert!(StpUtil::is_login(&token).await);
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_logout_with_invalid_token() {
    init();
    let fake = TokenValue::new("nonexistent_token_1234567890");
    let _ = StpUtil::logout(&fake).await;
    assert!(!StpUtil::is_login(&fake).await);
}

#[tokio::test]
async fn test_kick_out_not_logged_in_user() {
    init();
    let result = StpUtil::kick_out("nonexistent_user_xyz").await;
    let _ = result; // may be Ok or Err; should not panic
}

#[tokio::test]
async fn test_is_login_nonexistent_user_returns_false() {
    init();
    let fake = TokenValue::new("no_such_token_at_all_long_enough_16ch");
    assert!(!StpUtil::is_login(&fake).await);
}

#[tokio::test]
async fn test_is_login_by_login_id_not_logged_in() {
    init();
    assert!(!StpUtil::is_login_by_login_id("not_registered_user").await);
}

#[tokio::test]
async fn test_get_token_info_expired_token() {
    let mgr = setup::fresh_manager_with_config(setup::short_timeout_config(1));
    let token = mgr.login("user_expires").await.expect("login");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let result = mgr.get_token_info(&token).await;
    assert!(
        result.is_err(),
        "expired token should return error, got {:?}",
        result
    );
}

#[tokio::test]
async fn test_get_token_info_nonexistent_token() {
    init();
    let fake = TokenValue::new("nonexistent_token_long_enough_16ch");
    let result = StpUtil::get_token_info(&fake).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SaTokenError::TokenNotFound));
}

#[tokio::test]
async fn test_is_valid_empty_token() {
    init();
    let empty = TokenValue::new("");
    assert!(!StpUtil::is_login(&empty).await);
}

#[tokio::test]
async fn test_check_login_not_logged_in() {
    init();
    let fake = TokenValue::new("unused_token_value_long_enough_to_test");
    let result = StpUtil::check_login(&fake).await;
    assert!(result.is_err());
}
