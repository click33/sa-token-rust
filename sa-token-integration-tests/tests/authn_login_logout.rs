//! P0: Login / Logout / Kick-out / Multi-device integration tests.
//!
//! 覆盖 Manager 与 StpUtil 认证生命周期；失败路径匹配具体错误变体；
//! 过期用灰盒拨钟，禁止 sleep。

mod common;

use common::setup;
use sa_token_core::{
    LogoutMode, ReplacedLoginExitMode, ReplacedRange, SaTokenConfig, SaTokenError, StpUtil,
    config::TokenStyle, token::TokenValue,
};
use serial_test::serial;

fn init() {
    let _mgr = setup::shared_manager();
}

// ── Success: manager ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_login_creates_valid_token_with_login_id() {
    let mgr = setup::fresh_manager();
    let id = setup::unique_login_id("user");
    let token = mgr.login(&id).await.expect("login");
    assert!(!token.as_str().is_empty());
    setup::assert_logged_in(&mgr, &token, &id).await;
}

#[tokio::test]
async fn test_login_multiple_users_get_different_tokens() {
    let mgr = setup::fresh_manager();
    let t1 = mgr.login("user_a").await.expect("login a");
    let t2 = mgr.login("user_b").await.expect("login b");
    assert_ne!(t1.as_str(), t2.as_str());
    assert!(mgr.is_valid(&t1).await);
    assert!(mgr.is_valid(&t2).await);
}

#[tokio::test]
async fn test_logout_by_token_then_invalid() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_1").await.expect("login");
    mgr.logout(&token).await.expect("logout");
    assert!(!mgr.is_valid(&token).await);
    setup::assert_err(mgr.get_token_info(&token).await, "not_found");
}

#[tokio::test]
async fn test_logout_by_login_id() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_1").await.expect("login");
    mgr.logout_by_login_id("login", "user_1")
        .await
        .expect("logout_by_login_id");
    assert!(!mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_kick_out_returns_kicked_error() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_1").await.expect("login");
    mgr.kick_out("login", "user_1").await.expect("kick_out");
    assert!(!mgr.is_valid(&token).await);
    setup::assert_err(mgr.get_token_info(&token).await, "kicked");
}

#[tokio::test]
async fn test_is_concurrent_both_tokens_remain_valid() {
    let mgr = setup::fresh_manager();
    let t1 = mgr.login("user_1").await.expect("first");
    let t2 = mgr.login("user_1").await.expect("second");
    assert_ne!(t1.as_str(), t2.as_str());
    // 并发模式：两 token 必须同时有效（否则测的是顶号而非并发）
    assert!(mgr.is_valid(&t1).await, "first token must stay valid");
    assert!(mgr.is_valid(&t2).await, "second token must stay valid");
}

#[tokio::test]
async fn test_non_concurrent_replaced_error_and_terminal_gone() {
    let config = SaTokenConfig::builder()
        .timeout(3600)
        .token_style(TokenStyle::Uuid)
        .is_concurrent(false)
        .is_share(false)
        .auto_renew(false)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let t1 = mgr.login("u_rep").await.expect("first");
    let t2 = mgr.login("u_rep").await.expect("second");
    assert_ne!(t1.as_str(), t2.as_str());
    setup::assert_err(mgr.get_token_info(&t1).await, "replaced");
    assert!(mgr.is_valid(&t2).await);
    let terminals = mgr
        .get_terminal_list("default", "u_rep", None)
        .await
        .expect("terminals");
    assert!(terminals.iter().all(|t| t.token_value != t1.as_str()));
    assert!(terminals.iter().any(|t| t.token_value == t2.as_str()));
}

#[tokio::test]
async fn test_is_share_reuses_same_token() {
    let config = SaTokenConfig::builder()
        .is_share(true)
        .is_concurrent(true)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let t1 = mgr.login("user_share").await.expect("first");
    let t2 = mgr.login("user_share").await.expect("second");
    assert_eq!(t1.as_str(), t2.as_str());
    assert!(mgr.is_valid(&t1).await);
}

#[tokio::test]
async fn test_is_share_different_device_different_tokens() {
    // share 主要针对同账号映射；不同 device 通常仍各自登录
    let config = SaTokenConfig::builder()
        .is_share(true)
        .is_concurrent(true)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let t_web = mgr
        .login_with_options("user_1", None, Some("web".into()), None, None, None)
        .await
        .expect("web");
    let t_mobile = mgr
        .login_with_options("user_1", None, Some("mobile".into()), None, None, None)
        .await
        .expect("mobile");
    // share=true 时第二次 login（含 device）可能复用映射；若复用则同 token，否则两 token 都有效
    if t_web.as_str() == t_mobile.as_str() {
        assert!(mgr.is_valid(&t_web).await);
    } else {
        assert!(mgr.is_valid(&t_web).await);
        assert!(mgr.is_valid(&t_mobile).await);
    }
}

#[tokio::test]
async fn test_login_by_device_both_valid() {
    let mgr = setup::fresh_manager();
    let t_web = mgr
        .login_with_options("user_1", None, Some("web".into()), None, None, None)
        .await
        .expect("web");
    let t_mobile = mgr
        .login_with_options("user_1", None, Some("mobile".into()), None, None, None)
        .await
        .expect("mobile");
    assert_ne!(t_web.as_str(), t_mobile.as_str());
    assert!(mgr.is_valid(&t_web).await);
    assert!(mgr.is_valid(&t_mobile).await);
}

#[tokio::test]
async fn test_login_with_options_sets_device_and_type() {
    let mgr = setup::fresh_manager();
    let token = mgr
        .login_with_options(
            "user_1",
            Some("admin".into()),
            Some("iPhone".into()),
            None,
            None,
            None,
        )
        .await
        .expect("login");
    let info = mgr.get_token_info(&token).await.expect("info");
    assert_eq!(info.device.as_deref(), Some("iPhone"));
    assert_eq!(info.login_type.as_ref(), "admin");
}

#[tokio::test]
async fn test_login_with_extra_data() {
    let mgr = setup::fresh_manager();
    let extra = serde_json::json!({"ip": "192.168.1.1"});
    let token = mgr
        .login_with_options("user_1", None, None, Some(extra), None, None)
        .await
        .expect("login");
    let info = mgr.get_token_info(&token).await.expect("info");
    let stored = info.extra_data.expect("extra_data");
    assert_eq!(stored["ip"], "192.168.1.1");
}

#[tokio::test]
async fn test_max_login_count_overflow_kickout() {
    let config = SaTokenConfig::builder()
        .is_concurrent(true)
        .max_login_count(1)
        .overflow_logout_mode(LogoutMode::KickOut)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let t1 = mgr.login("u_overflow").await.expect("t1");
    let t2 = mgr.login("u_overflow").await.expect("t2");
    setup::assert_err(mgr.get_token_info(&t1).await, "kicked");
    assert!(mgr.is_valid(&t2).await);
}

#[tokio::test]
async fn test_max_login_count_overflow_logout_deletes_old() {
    let config = SaTokenConfig::builder()
        .is_concurrent(true)
        .max_login_count(1)
        .overflow_logout_mode(LogoutMode::Logout)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let t1 = mgr.login("u_ov_logout").await.expect("t1");
    let t2 = mgr.login("u_ov_logout").await.expect("t2");
    // Logout 模式：旧键删除，表现为 TokenNotFound（非 KickOut）
    setup::assert_err(mgr.get_token_info(&t1).await, "not_found");
    assert!(mgr.is_valid(&t2).await);
}

#[tokio::test]
async fn test_max_login_count_overflow_replaced() {
    let config = SaTokenConfig::builder()
        .is_concurrent(true)
        .max_login_count(1)
        .overflow_logout_mode(LogoutMode::Replaced)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let t1 = mgr.login("u_ov_rep").await.expect("t1");
    let t2 = mgr.login("u_ov_rep").await.expect("t2");
    setup::assert_err(mgr.get_token_info(&t1).await, "replaced");
    assert!(mgr.is_valid(&t2).await);
}

#[tokio::test]
async fn test_replaced_exit_mode_new_device_rejects() {
    let config = SaTokenConfig::builder()
        .is_concurrent(false)
        .is_share(false)
        .replaced_login_exit_mode(ReplacedLoginExitMode::NewDevice)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let t1 = mgr.login("u_keep").await.expect("first");
    let second = mgr.login("u_keep").await;
    setup::assert_err(second, "replaced");
    assert!(mgr.is_valid(&t1).await, "old device must remain");
}

#[tokio::test]
async fn test_replaced_range_curr_device_only() {
    let config = SaTokenConfig::builder()
        .is_concurrent(false)
        .is_share(false)
        .replaced_range(ReplacedRange::CurrDeviceType)
        .replaced_login_exit_mode(ReplacedLoginExitMode::OldDevice)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let t_pc = mgr
        .login_with_options("u_range", None, Some("PC".into()), None, None, None)
        .await
        .expect("pc");
    let t_app = mgr
        .login_with_options("u_range", None, Some("APP".into()), None, None, None)
        .await
        .expect("app");
    // CurrDeviceType + 不同 device：APP 登录不应顶掉 PC
    assert!(
        mgr.is_valid(&t_pc).await,
        "PC session should survive APP login under CurrDeviceType"
    );
    assert!(mgr.is_valid(&t_app).await);
}

// ── StpUtil ────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn test_stp_util_login_and_logout() {
    init();
    let id = setup::unique_login_id("stp");
    let token = StpUtil::login(&id).await.expect("login");
    setup::assert_stp_logged_in(&token, &id).await;
    StpUtil::logout_by_token(&token)
        .await
        .expect("logout_by_token");
    assert!(!StpUtil::is_login(&token).await);
}

#[tokio::test]
#[serial]
async fn test_stp_util_login_with_type() {
    init();
    let id = setup::unique_login_id("admin");
    let token = StpUtil::login_with_type(&id, "admin")
        .await
        .expect("login_with_type");
    let info = StpUtil::get_token_info(&token).await.expect("info");
    assert_eq!(info.login_type.as_ref(), "admin");
    assert_eq!(info.login_id.as_ref(), id);
}

#[tokio::test]
#[serial]
async fn test_get_all_tokens_after_concurrent() {
    init();
    let id = setup::unique_login_id("multi");
    let t1 = StpUtil::login(&id).await.expect("1");
    let t2 = StpUtil::login(&id).await.expect("2");
    let tokens = StpUtil::get_all_tokens_by_login_id(&id)
        .await
        .expect("tokens");
    assert_eq!(tokens.len(), 2);
    assert!(tokens.iter().any(|t| t.as_str() == t1.as_str()));
    assert!(tokens.iter().any(|t| t.as_str() == t2.as_str()));
    assert!(StpUtil::is_login(&t1).await);
    assert!(StpUtil::is_login(&t2).await);
}

#[tokio::test]
#[serial]
async fn test_is_login_by_login_id() {
    init();
    let id = setup::unique_login_id("by_id");
    let token = StpUtil::login(&id).await.expect("login");
    assert!(StpUtil::is_login_by_login_id(&id).await);
    assert!(StpUtil::is_login(&token).await);
}

// ── Failure ────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn test_logout_invalid_token_is_ok_and_still_not_login() {
    init();
    let fake = TokenValue::new("nonexistent_token_1234567890");
    // 契约：无效 token 登出不得 panic；登出后仍未登录
    StpUtil::logout(&fake)
        .await
        .expect("logout missing token should be Ok");
    assert!(!StpUtil::is_login(&fake).await);
}

#[tokio::test]
#[serial]
async fn test_kick_out_not_logged_in_user_is_idempotent() {
    init();
    let id = setup::unique_login_id("kick_nobody");
    StpUtil::kick_out(&id)
        .await
        .expect("kick missing user should be Ok");
    assert!(!StpUtil::is_login_by_login_id(&id).await);
}

#[tokio::test]
#[serial]
async fn test_is_login_nonexistent_false() {
    init();
    let fake = TokenValue::new("no_such_token_at_all_long_enough_16ch");
    assert!(!StpUtil::is_login(&fake).await);
}

#[tokio::test]
async fn test_get_token_info_expired_via_clock() {
    let mgr = setup::fresh_manager();
    let token = mgr.login("user_expires").await.expect("login");
    setup::expire_token(&mgr, &token).await;
    let result = mgr.get_token_info(&token).await;
    assert!(
        result.is_err(),
        "expired token should error, got {result:?}"
    );
    // 过期可能映射为 TokenExpired 或 TokenNotFound（存储 TTL 清理）
    match result {
        Err(SaTokenError::TokenExpired | SaTokenError::TokenNotFound) => {}
        other => panic!("unexpected expired result: {other:?}"),
    }
}

#[tokio::test]
#[serial]
async fn test_get_token_info_nonexistent() {
    init();
    let fake = TokenValue::new("nonexistent_token_long_enough_16ch");
    setup::assert_err(StpUtil::get_token_info(&fake).await, "not_found");
}

#[tokio::test]
#[serial]
async fn test_is_valid_empty_token() {
    init();
    let empty = TokenValue::new("");
    assert!(!StpUtil::is_login(&empty).await);
}

#[tokio::test]
#[serial]
async fn test_check_login_not_logged_in() {
    init();
    let fake = TokenValue::new("unused_token_value_long_enough_to_test");
    let result = StpUtil::check_login(&fake).await;
    assert!(
        matches!(
            result,
            Err(SaTokenError::NotLogin | SaTokenError::TokenNotFound)
        ),
        "got {result:?}"
    );
}
