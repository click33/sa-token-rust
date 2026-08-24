//! 多账号体系 + 多设备终端端到端集成测试

mod common;

use std::sync::{Arc, OnceLock};

use common::setup;
use sa_token_core::{SaLogic, StpUtil};

fn stp_util_manager() -> Arc<sa_token_core::SaTokenManager> {
    static MGR: OnceLock<Arc<sa_token_core::SaTokenManager>> = OnceLock::new();
    MGR.get_or_init(|| {
        let mgr = setup::fresh_manager();
        let _init = StpUtil::try_init_manager(mgr.as_ref().clone());
        mgr
    })
    .clone()
}

#[tokio::test]
async fn test_multi_account_isolation() {
    let mgr = setup::fresh_manager();
    let admin = SaLogic::new("admin", mgr.as_ref().clone());
    let user = SaLogic::new("user", mgr.as_ref().clone());

    let admin_token = admin.login("10001").await.expect("admin login");
    let user_token = user.login("10001").await.expect("user login");

    assert_ne!(admin_token.as_str(), user_token.as_str());
    assert!(admin.is_valid(&admin_token).await);
    assert!(user.is_valid(&user_token).await);

    admin
        .set_permissions("10001", vec!["admin:read".to_string()])
        .await
        .expect("admin perms");
    user.set_permissions("10001", vec!["user:read".to_string()])
        .await
        .expect("user perms");

    assert_eq!(
        admin.get_permissions("10001").await.expect("get admin"),
        vec!["admin:read".to_string()]
    );
    assert_eq!(
        user.get_permissions("10001").await.expect("get user"),
        vec!["user:read".to_string()]
    );
    assert!(
        !admin
            .has_permission("10001", "user:read")
            .await
            .expect("check")
    );
    assert!(
        !user
            .has_permission("10001", "admin:read")
            .await
            .expect("check")
    );

    assert_eq!(
        admin
            .get_terminal_list("10001", None)
            .await
            .expect("admin terminals")
            .len(),
        1
    );
    assert_eq!(
        user.get_terminal_list("10001", None)
            .await
            .expect("user terminals")
            .len(),
        1
    );
}

#[tokio::test]
async fn test_terminal_end_to_end() {
    let mgr = setup::fresh_manager();
    let admin = SaLogic::new("admin", mgr.as_ref().clone());

    let pc_token = admin
        .login_with_device("10001", Some("PC".to_string()), None)
        .await
        .expect("pc");
    let app_token = admin
        .login_with_device("10001", Some("APP".to_string()), None)
        .await
        .expect("app");

    assert!(admin.is_valid(&pc_token).await);
    assert!(admin.is_valid(&app_token).await);
    assert_eq!(
        admin
            .get_terminal_list("10001", Some("PC"))
            .await
            .expect("pc list")
            .len(),
        1
    );
    assert_eq!(
        admin
            .get_terminal_list("10001", None)
            .await
            .expect("all")
            .len(),
        2
    );

    admin.logout(&pc_token).await.expect("logout pc");
    assert!(!admin.is_valid(&pc_token).await);
    assert!(admin.is_valid(&app_token).await);
    assert_eq!(
        admin
            .get_terminal_list("10001", None)
            .await
            .expect("after logout")
            .len(),
        1
    );

    let terminal = admin
        .get_terminal_info_by_token(&app_token)
        .await
        .expect("info")
        .expect("some");
    assert_eq!(terminal.device_type, "APP");
}

#[tokio::test]
async fn test_terminal_index_monotonic() {
    let mgr = setup::fresh_manager();
    let admin = SaLogic::new("admin", mgr.as_ref().clone());

    let t1 = admin.login("10001").await.expect("t1");
    let t2 = admin.login("10001").await.expect("t2");
    let t3 = admin.login("10001").await.expect("t3");
    assert!(admin.is_valid(&t1).await);
    assert!(admin.is_valid(&t2).await);
    assert!(admin.is_valid(&t3).await);

    let terminals = admin.get_terminal_list("10001", None).await.expect("list");
    assert_eq!(terminals[0].index, 1);
    assert_eq!(terminals[1].index, 2);
    assert_eq!(terminals[2].index, 3);

    admin.logout(&t2).await.expect("logout t2");
    let t4 = admin.login("10001").await.expect("t4");

    let terminals = admin.get_terminal_list("10001", None).await.expect("list2");
    let t4_terminal = terminals
        .iter()
        .find(|t| t.token_value == t4.as_str())
        .expect("t4 in list");
    assert_eq!(t4_terminal.index, 4);
}

#[tokio::test]
async fn test_default_account_backward_compatible() {
    let mgr = stp_util_manager();
    let id = setup::unique_login_id("compat");
    let token = mgr.login(&id).await.expect("login");
    let terminals = mgr
        .get_terminal_list("default", &id, None)
        .await
        .expect("mgr terminals");
    assert_eq!(terminals.len(), 1);
    assert_eq!(terminals[0].token_value, token.as_str());

    let stp_terminals = StpUtil::get_terminal_list(&id, None)
        .await
        .expect("stp terminals");
    assert_eq!(stp_terminals.len(), 1);
}

#[tokio::test]
async fn test_stp_logic_facade_login_isolation() {
    let mgr = stp_util_manager();
    let shop = SaLogic::new("shop", mgr.as_ref().clone());
    let via_util = StpUtil::stp_logic("shop").expect("stp_logic");
    assert_eq!(shop.login_type(), "shop");
    assert_eq!(via_util.login_type(), "shop");

    let id = setup::unique_login_id("shop_user");
    let token = shop.login(&id).await.expect("shop login");
    assert!(shop.is_valid(&token).await);
    assert!(!StpUtil::is_login_by_login_id(&id).await);
}
