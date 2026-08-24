//! Nonce replay-protection integration tests.
//!
//! 安全契约：TTL 内二次 consume → NonceAlreadyUsed；
//! TTL 过后键过期，允许新窗口（重放窗口 = TTL）。过期用拨存储键，禁止 sleep。

mod common;

use common::setup;
use sa_token_adapter::SaStorage;
use sa_token_core::{NonceManager, SaTokenConfig, SaTokenError, config::TokenStyle};

#[tokio::test]
async fn test_nonce_generate_unique() {
    let storage = setup::memory_storage();
    let mgr = NonceManager::new(storage, 60);
    let n1 = mgr.generate();
    let n2 = mgr.generate();
    assert_ne!(n1, n2);
    assert!(n1.starts_with("nonce_"));
}

#[tokio::test]
async fn test_nonce_consume_once_then_reject() {
    let storage = setup::memory_storage();
    let mgr = NonceManager::new(storage, 60);
    let nonce = mgr.generate();
    mgr.validate_and_consume(&nonce, "user_1")
        .await
        .expect("first consume");
    let second = mgr.validate_and_consume(&nonce, "user_1").await;
    setup::assert_err(second, "nonce_used");
}

#[tokio::test]
async fn test_nonce_login_replay_rejected() {
    let config = SaTokenConfig::builder()
        .enable_nonce(true)
        .nonce_timeout(60)
        .token_style(TokenStyle::Uuid)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let nonce_mgr = NonceManager::from_dao(mgr.dao().clone(), 60);
    let nonce = nonce_mgr.generate();
    let token = mgr
        .login_with_options("user_nonce", None, None, None, Some(nonce.clone()), None)
        .await
        .expect("first login");
    assert!(mgr.is_valid(&token).await);
    let replay = mgr
        .login_with_options("user_nonce", None, None, None, Some(nonce), None)
        .await;
    assert!(matches!(replay, Err(SaTokenError::NonceAlreadyUsed)));
}

#[tokio::test]
async fn test_nonce_after_ttl_key_gone_allows_reuse() {
    // 契约注释：重放防护窗口 = nonce TTL；键过期后视为新窗口（非永久黑名单）
    let storage = setup::memory_storage();
    let mgr = NonceManager::new(storage.clone(), 60);
    let nonce = mgr.generate();
    mgr.validate_and_consume(&nonce, "user_ttl")
        .await
        .expect("consume");
    // 灰盒：直接删 nonce 键模拟 TTL 到期
    let key = sa_token_core::keys::SaKeys::new("sa:").nonce(&nonce);
    storage.delete(&key).await.expect("delete nonce key");
    mgr.validate_and_consume(&nonce, "user_ttl")
        .await
        .expect("after TTL window, reuse allowed by design");
}

#[tokio::test]
async fn test_nonce_empty_rejected() {
    let storage = setup::memory_storage();
    let mgr = NonceManager::new(storage, 60);
    let result = mgr.validate_and_consume("", "user").await;
    assert!(result.is_err());
}
