use common::setup;
use sa_token_core::SaTokenConfig;

mod common;

/// Token-Session 删除后存储键必须消失（禁止只测 get 重建后的空字段）。
#[tokio::test]
async fn test_delete_token_session_clears_storage_key() {
    let config = SaTokenConfig::builder()
        .right_now_create_token_session(true)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("ts_user").await.expect("login");
    let mut session = mgr.get_token_session(&token).await.expect("get");
    session.set("k", "v").expect("set");
    mgr.save_token_session(&token, &session)
        .await
        .expect("save");
    let key = mgr.keys().token_session(token.as_str());
    assert!(
        mgr.storage().get(&key).await.expect("get").is_some(),
        "key must exist after save"
    );
    mgr.delete_token_session(&token).await.expect("delete");
    assert!(
        mgr.storage().get(&key).await.expect("get2").is_none(),
        "token_session storage key must be deleted"
    );
}
