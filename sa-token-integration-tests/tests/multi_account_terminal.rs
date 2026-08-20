//! 多账号体系 + 多设备终端端到端集成测试

mod common;

use std::sync::{Arc, OnceLock};

use common::setup;
use sa_token_core::{SaLogic, StpUtil};

fn stp_util_manager() -> Arc<sa_token_core::SaTokenManager> {
    static MGR: OnceLock<Arc<sa_token_core::SaTokenManager>> = OnceLock::new();
    MGR.get_or_init(|| {
        let mgr = setup::fresh_manager();
        let _ = StpUtil::try_init_manager(mgr.as_ref().clone());
        mgr
    })
    .clone()
}

#[tokio::test]
async fn test_multi_account_isolation() {
    let mgr = setup::fresh_manager();
    let admin = SaLogic::new("admin", mgr.as_ref().clone());
    let user = SaLogic::new("user", mgr.as_ref().clone());

    let admin_token = admin.login("10001").await.unwrap();
    let user_token = user.login("10001").await.unwrap();

    assert_ne!(admin_token.as_str(), user_token.as_str());
    assert!(admin.is_valid(&admin_token).await);
    assert!(user.is_valid(&user_token).await);

    admin
        .set_permissions("10001", vec!["admin:read".to_string()])
        .await
        .unwrap();
    user.set_permissions("10001", vec!["user:read".to_string()])
        .await
        .unwrap();

    assert_eq!(
        admin.get_permissions("10001").await.unwrap(),
        vec!["admin:read".to_string()]
    );
    assert_eq!(
        user.get_permissions("10001").await.unwrap(),
        vec!["user:read".to_string()]
    );

    assert_eq!(
        admin.get_terminal_list("10001", None).await.unwrap().len(),
        1
    );
    assert_eq!(
        user.get_terminal_list("10001", None).await.unwrap().len(),
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
        .unwrap();
    let app_token = admin
        .login_with_device("10001", Some("APP".to_string()), None)
        .await
        .unwrap();

    assert_eq!(
        admin
            .get_terminal_list("10001", Some("PC"))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        admin.get_terminal_list("10001", None).await.unwrap().len(),
        2
    );

    admin.logout(&pc_token).await.unwrap();
    assert_eq!(
        admin.get_terminal_list("10001", None).await.unwrap().len(),
        1
    );

    let terminal = admin
        .get_terminal_info_by_token(&app_token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(terminal.device_type, "APP");
}

#[tokio::test]
async fn test_terminal_index_monotonic() {
    let mgr = setup::fresh_manager();
    let admin = SaLogic::new("admin", mgr.as_ref().clone());

    let t1 = admin.login("10001").await.unwrap();
    let t2 = admin.login("10001").await.unwrap();
    let t3 = admin.login("10001").await.unwrap();

    let terminals = admin.get_terminal_list("10001", None).await.unwrap();
    assert_eq!(terminals[0].index, 1);
    assert_eq!(terminals[1].index, 2);
    assert_eq!(terminals[2].index, 3);

    admin.logout(&t2).await.unwrap();
    let t4 = admin.login("10001").await.unwrap();

    let terminals = admin.get_terminal_list("10001", None).await.unwrap();
    let t4_terminal = terminals
        .iter()
        .find(|t| t.token_value == t4.as_str())
        .unwrap();
    assert_eq!(t4_terminal.index, 4);

    let _ = (t1, t3);
}

#[tokio::test]
async fn test_default_account_backward_compatible() {
    let mgr = stp_util_manager();

    let token = mgr.login("u").await.unwrap();
    let terminals = mgr.get_terminal_list("default", "u", None).await.unwrap();
    assert_eq!(terminals.len(), 1);
    assert_eq!(terminals[0].token_value, token.as_str());

    let stp_terminals = StpUtil::get_terminal_list("u", None).await.unwrap();
    assert_eq!(stp_terminals.len(), 1);

    let session = mgr.get_session("u").await.unwrap();
    assert_eq!(session.id, "u");
}

#[tokio::test]
async fn test_stp_logic_facade_clone() {
    let mgr = stp_util_manager();

    let logic = SaLogic::new("shop", mgr.as_ref().clone());
    let via_util = StpUtil::stp_logic("shop").unwrap();
    assert_eq!(logic.login_type(), "shop");
    assert_eq!(via_util.login_type(), "shop");

    // Deprecated no-ops still compile for migration compatibility.
    #[allow(deprecated)]
    {
        StpUtil::put_stp_logic(logic.clone());
        StpUtil::remove_stp_logic("shop");
    }
}
