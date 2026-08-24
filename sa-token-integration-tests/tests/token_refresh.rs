//! Refresh Token：走 enable_refresh_token 真实 login → refresh 链路。

mod common;

use common::setup;
use sa_token_core::{
    RefreshTokenManager, SaTokenConfig, SaTokenError, config::TokenStyle, keys::LOGIN_TYPE_DEFAULT,
};

#[tokio::test]
async fn test_login_refresh_invalidates_old_access() {
    let config = SaTokenConfig::builder()
        .enable_refresh_token(true)
        .refresh_token_timeout(86400)
        .timeout(3600)
        .token_style(TokenStyle::Uuid)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let access = mgr.login("user_rt").await.expect("login");
    let info = mgr.get_token_info(&access).await.expect("info");
    let refresh = info.refresh_token.expect("refresh_token issued");

    let refresh_mgr = RefreshTokenManager::from_dao(mgr.dao().clone());
    let (new_access, login_id) = refresh_mgr
        .refresh_access_token(&refresh)
        .await
        .expect("refresh_access_token");
    assert_eq!(login_id, "user_rt");
    assert_ne!(new_access.as_str(), access.as_str());
    assert!(mgr.is_valid(&new_access).await);
    assert!(
        !mgr.is_valid(&access).await,
        "old access must be invalid after refresh"
    );
}

#[tokio::test]
async fn test_refresh_unknown_token_not_found() {
    let config = SaTokenConfig::builder()
        .enable_refresh_token(true)
        .refresh_token_timeout(86400)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let refresh_mgr = RefreshTokenManager::from_dao(mgr.dao().clone());
    let result = refresh_mgr
        .refresh_access_token("no_such_refresh_token_value")
        .await;
    assert!(
        matches!(
            result,
            Err(SaTokenError::RefreshTokenNotFound | SaTokenError::InvalidToken(_))
        ),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_revoke_all_refresh_tokens_for_user() {
    let config = SaTokenConfig::builder()
        .enable_refresh_token(true)
        .refresh_token_timeout(86400)
        .timeout(3600)
        .is_concurrent(true)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let a1 = mgr.login("user_revoke").await.expect("login1");
    let a2 = mgr.login("user_revoke").await.expect("login2");
    let r1 = mgr
        .get_token_info(&a1)
        .await
        .expect("i1")
        .refresh_token
        .expect("r1");
    let r2 = mgr
        .get_token_info(&a2)
        .await
        .expect("i2")
        .refresh_token
        .expect("r2");

    let refresh_mgr = RefreshTokenManager::from_dao(mgr.dao().clone());
    refresh_mgr
        .revoke_all_for_user(LOGIN_TYPE_DEFAULT, "user_revoke")
        .await
        .expect("revoke_all");

    let e1 = refresh_mgr.refresh_access_token(&r1).await;
    let e2 = refresh_mgr.refresh_access_token(&r2).await;
    assert!(e1.is_err(), "r1 must be revoked: {e1:?}");
    assert!(e2.is_err(), "r2 must be revoked: {e2:?}");
}
