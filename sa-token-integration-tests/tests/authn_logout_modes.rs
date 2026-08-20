//! Phase2: logout 三模式 / StpInterface / switch_to 集成测试

mod common;

use async_trait::async_trait;
use sa_token_core::{
    LogoutMode, SaTokenConfig, SaTokenError, SaTokenManager, StpInterface, StpUtil,
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
    let token = mgr.login("u_kick").await.unwrap();
    mgr.kick_out_by_token(&token).await.unwrap();
    assert!(matches!(
        mgr.get_token_info(&token).await,
        Err(SaTokenError::AccountKickedOut)
    ));
}

#[tokio::test]
async fn replaced_marks_old_token_on_non_concurrent_login() {
    let mgr = mgr_with_config(SaTokenConfig::builder().is_concurrent(false).build_config());
    let t1 = mgr.login("u_rep").await.unwrap();
    let _t2 = mgr.login("u_rep").await.unwrap();
    assert!(matches!(
        mgr.get_token_info(&t1).await,
        Err(SaTokenError::AccountReplaced)
    ));
}

#[tokio::test]
async fn stp_interface_provides_permissions() {
    let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), SaTokenConfig::default())
        .with_stp_interface(Arc::new(MockStpInterface));
    let perms = mgr.get_permissions("any").await.unwrap();
    assert!(perms.contains(&"from:interface".to_string()));
}

#[tokio::test]
async fn switch_to_overrides_login_id_in_context() {
    let mgr = mgr_with_config(SaTokenConfig::default());
    let token = mgr.login("real_user").await.unwrap();
    let ctx = sa_token_core::SaTokenContext::builder()
        .token(token.clone())
        .login_id("real_user")
        .build();
    sa_token_core::SaTokenContext::set_current(ctx);
    StpUtil::switch_to("temp_user");
    assert_eq!(
        StpUtil::get_login_id_as_string().await.unwrap(),
        "temp_user"
    );
    StpUtil::end_switch();
    assert_eq!(
        mgr.get_token_info(&token).await.unwrap().login_id,
        "real_user"
    );
    assert!(!StpUtil::is_switch());
}

#[tokio::test]
async fn max_login_count_enforces_overflow_mode() {
    let mgr = mgr_with_config(
        SaTokenConfig::builder()
            .is_concurrent(true)
            .max_login_count(1)
            .overflow_logout_mode(LogoutMode::KickOut)
            .build_config(),
    );
    let t1 = mgr.login("u_overflow").await.unwrap();
    let t2 = mgr.login("u_overflow").await.unwrap();
    assert!(matches!(
        mgr.get_token_info(&t1).await,
        Err(SaTokenError::AccountKickedOut)
    ));
    assert!(mgr.is_valid(&t2).await);
}

#[tokio::test]
async fn token_session_separate_from_account_session() {
    let mgr = mgr_with_config(
        SaTokenConfig::builder()
            .right_now_create_token_session(true)
            .build_config(),
    );
    let token = mgr.login("u_ts").await.unwrap();
    let mut ts = mgr.get_token_session(&token).await.unwrap();
    ts.set("foo", "bar").unwrap();
    mgr.save_token_session(&token, &ts).await.unwrap();
    let account = mgr.get_session("u_ts").await.unwrap();
    assert!(account.get::<String>("foo").is_none());
}
