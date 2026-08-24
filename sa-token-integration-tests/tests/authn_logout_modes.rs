//! Phase2: logout 三模式 / StpInterface / switch_to 集成测试

mod common;

use async_trait::async_trait;
use common::setup;
use sa_token_core::{
    LogoutMode, SaTokenConfig, SaTokenManager, StpInterface, StpUtil,
};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

struct MockStpInterface;

#[async_trait]
impl StpInterface for MockStpInterface {
    async fn get_permission_list(
        &self,
        _login_id: &str,
        _login_type: &str,
    ) -> sa_token_core::SaTokenResult<Vec<String>> {
        Ok(vec!["from:interface".to_string()])
    }

    async fn get_role_list(
        &self,
        _login_id: &str,
        _login_type: &str,
    ) -> sa_token_core::SaTokenResult<Vec<String>> {
        Ok(vec!["admin".to_string()])
    }
}

fn mgr_with_config(config: SaTokenConfig) -> Arc<SaTokenManager> {
    Arc::new(SaTokenManager::new(Arc::new(MemoryStorage::new()), config))
}

#[tokio::test]
async fn kickout_marks_token_as_kicked_out() {
    let mgr = mgr_with_config(SaTokenConfig::default());
    let token = mgr.login("u_kick").await.expect("login");
    mgr.kick_out_by_token(&token).await.expect("kick");
    setup::assert_err(mgr.get_token_info(&token).await, "kicked");
}

#[tokio::test]
async fn replaced_marks_old_token_on_non_concurrent_login() {
    let mgr = mgr_with_config(SaTokenConfig::builder().is_concurrent(false).build_config());
    let t1 = mgr.login("u_rep").await.expect("t1");
    let t2 = mgr.login("u_rep").await.expect("t2");
    setup::assert_err(mgr.get_token_info(&t1).await, "replaced");
    assert!(mgr.is_valid(&t2).await);
}

#[tokio::test]
async fn stp_interface_provides_permissions_for_has_check() {
    let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), SaTokenConfig::default())
        .with_stp_interface(Arc::new(MockStpInterface));
    let perms = mgr.get_permissions("any").await.expect("perms");
    assert!(perms.contains(&"from:interface".to_string()));
    let roles = mgr.get_roles("any").await.expect("roles");
    assert!(roles.contains(&"admin".to_string()));
    // 未配置用户不应拿到接口假数据以外的权限
    assert!(!perms.contains(&"missing:perm".to_string()));
}

#[tokio::test]
async fn switch_to_overrides_and_end_switch_restores() {
    let mgr = mgr_with_config(SaTokenConfig::default());
    let _init = StpUtil::try_init_manager((*mgr).clone());
    let token = mgr.login("real_user").await.expect("login");
    let ctx = sa_token_core::SaTokenContext::builder()
        .token(token.clone())
        .login_id("real_user")
        .build();
    sa_token_core::SaTokenContext::set_current(ctx);
    StpUtil::switch_to("temp_user");
    assert_eq!(
        StpUtil::get_login_id_as_string().await.expect("switched"),
        "temp_user"
    );
    StpUtil::end_switch();
    // end_switch 后上下文 login_id 必须恢复
    assert_eq!(
        StpUtil::get_login_id_as_string().await.expect("restored"),
        "real_user"
    );
    assert!(!StpUtil::is_switch());
    assert_eq!(
        mgr.get_token_info(&token)
            .await
            .expect("info")
            .login_id
            .as_ref(),
        "real_user"
    );
    sa_token_core::SaTokenContext::clear();
}

#[tokio::test]
async fn max_login_count_enforces_overflow_kickout() {
    let mgr = mgr_with_config(
        SaTokenConfig::builder()
            .is_concurrent(true)
            .max_login_count(1)
            .overflow_logout_mode(LogoutMode::KickOut)
            .build_config(),
    );
    let t1 = mgr.login("u_overflow").await.expect("t1");
    let t2 = mgr.login("u_overflow").await.expect("t2");
    setup::assert_err(mgr.get_token_info(&t1).await, "kicked");
    assert!(mgr.is_valid(&t2).await);
}

#[tokio::test]
async fn token_session_separate_from_account_session() {
    let mgr = mgr_with_config(
        SaTokenConfig::builder()
            .right_now_create_token_session(true)
            .build_config(),
    );
    let token = mgr.login("u_ts").await.expect("login");
    let mut ts = mgr.get_token_session(&token).await.expect("token session");
    ts.set("foo", "bar").expect("set");
    mgr.save_token_session(&token, &ts).await.expect("save");
    let account = mgr.get_session("u_ts").await.expect("account");
    assert!(account.get::<String>("foo").is_none());
}
