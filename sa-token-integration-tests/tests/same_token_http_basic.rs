//! Same-Token / HTTP Basic 校验集成测试。

mod common;

use common::setup;
use sa_token_core::{SaTokenContext, SaTokenError, http_basic, same_token};

#[tokio::test]
async fn test_http_basic_decode_and_ct_eq() {
    assert_eq!(
        http_basic::decode_basic_authorization("Basic dXNlcjpwYXNz"),
        Some("user:pass".into())
    );
    assert!(http_basic::decode_basic_authorization("Bearer x").is_none());
    assert!(http_basic::ct_eq(b"abc", b"abc"));
    assert!(!http_basic::ct_eq(b"abc", b"abd"));
}

#[tokio::test]
async fn test_same_token_roundtrip_via_stp() {
    let _mgr = setup::shared_manager();
    let token = same_token::get_token().await.expect("get_token");
    assert!(!token.is_empty());
    same_token::check_token(&token)
        .await
        .expect("check current");
    assert!(same_token::is_valid(&token).await.expect("valid"));
    assert!(
        !same_token::is_valid("totally_wrong_token_value")
            .await
            .expect("invalid")
    );
}

#[tokio::test]
async fn test_http_basic_check_fails_without_authorization() {
    let _mgr = setup::shared_manager();
    SaTokenContext::clear();
    let err = http_basic::check("realm", "user:pass");
    assert!(
        matches!(err, Err(SaTokenError::BasicAuthFailed { .. })),
        "without Authorization header, got {err:?}"
    );
}
