//! OAuth2 授权码 / PKCE / 密码拒绝 / refresh 旧 access 失效。

mod common;

use async_trait::async_trait;
use common::setup;
use sa_token_core::oauth2::{CodeChallengeMethod, OAuth2Client, OAuth2Manager, PkceChallenge};
use sa_token_core::{PasswordVerifier, SaTokenError};
use std::sync::Arc;

struct RejectPassword;

#[async_trait]
impl PasswordVerifier for RejectPassword {
    async fn verify_password(
        &self,
        _username: &str,
        _password: &str,
    ) -> sa_token_core::SaTokenResult<()> {
        Err(SaTokenError::OAuth2InvalidCredentials)
    }
}

struct AcceptPassword;

#[async_trait]
impl PasswordVerifier for AcceptPassword {
    async fn verify_password(
        &self,
        _username: &str,
        _password: &str,
    ) -> sa_token_core::SaTokenResult<()> {
        Ok(())
    }
}

fn client_confidential() -> OAuth2Client {
    OAuth2Client {
        client_id: "app".into(),
        client_secret_hash: String::new(),
        client_secret: "secret".into(),
        redirect_uris: vec!["https://app.example/cb".into()],
        grant_types: vec![
            "authorization_code".into(),
            "refresh_token".into(),
            "password".into(),
            "client_credentials".into(),
        ],
        scope: vec!["read".into(), "write".into()],
        public_client: false,
    }
}

#[tokio::test]
async fn test_authorization_code_exchange_and_second_use_fails() {
    let mgr = OAuth2Manager::new(setup::memory_storage()).with_ttl(60, 3600, 86400);
    let client = client_confidential();
    mgr.register_client_with_secret(client.clone(), "secret")
        .await
        .expect("register");
    let code = mgr
        .issue_authorization_code(
            client.client_id.clone(),
            "user1".into(),
            "https://app.example/cb".into(),
            vec!["read".into()],
            None,
            None,
        )
        .await
        .expect("code");
    let token = mgr
        .exchange_code_for_token(
            &code.code,
            &client.client_id,
            "secret",
            "https://app.example/cb",
            None,
        )
        .await
        .expect("exchange");
    assert!(!token.access_token.is_empty());
    let again = mgr
        .exchange_code_for_token(
            &code.code,
            &client.client_id,
            "secret",
            "https://app.example/cb",
            None,
        )
        .await;
    assert!(again.is_err(), "code must be single-use");
}

#[tokio::test]
async fn test_pkce_s256_success_and_bad_verifier() {
    let mgr = OAuth2Manager::new(setup::memory_storage())
        .with_ttl(60, 3600, 86400)
        .with_require_pkce(true);
    let mut client = client_confidential();
    client.public_client = true;
    client.client_secret.clear();
    mgr.register_client(&client).await.expect("register");

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let pkce = PkceChallenge::from_verifier_s256(verifier).expect("pkce");
    assert!(matches!(
        pkce.code_challenge_method,
        CodeChallengeMethod::S256
    ));

    let code = mgr
        .issue_authorization_code(
            client.client_id.clone(),
            "user_pkce".into(),
            "https://app.example/cb".into(),
            vec!["read".into()],
            Some(pkce),
            None,
        )
        .await
        .expect("code");

    let bad = mgr
        .exchange_code_for_token(
            &code.code,
            &client.client_id,
            "",
            "https://app.example/cb",
            Some("wrong_verifier_that_is_long_enough_43chars_min_xx"),
        )
        .await;
    assert!(bad.is_err(), "bad PKCE verifier must fail");

    let pkce2 = PkceChallenge::from_verifier_s256(verifier).expect("pkce2");
    let code2 = mgr
        .issue_authorization_code(
            client.client_id.clone(),
            "user_pkce".into(),
            "https://app.example/cb".into(),
            vec!["read".into()],
            Some(pkce2),
            None,
        )
        .await
        .expect("code2");
    let ok = mgr
        .exchange_code_for_token(
            &code2.code,
            &client.client_id,
            "",
            "https://app.example/cb",
            Some(verifier),
        )
        .await
        .expect("pkce ok");
    assert!(!ok.access_token.is_empty());
}

#[tokio::test]
async fn test_password_grant_rejected_by_verifier() {
    let mgr = OAuth2Manager::new(setup::memory_storage())
        .with_ttl(60, 3600, 86400)
        .with_password_verifier(Arc::new(RejectPassword));
    let client = client_confidential();
    mgr.register_client_with_secret(client.clone(), "secret")
        .await
        .expect("register");
    let result = mgr
        .password_grant(
            &client.client_id,
            "secret",
            "alice",
            "bad",
            vec!["read".into()],
        )
        .await;
    assert!(result.is_err(), "RejectPassword must deny");
}

#[tokio::test]
async fn test_refresh_invalidates_old_access_verify() {
    let mgr = OAuth2Manager::new(setup::memory_storage())
        .with_ttl(60, 3600, 86400)
        .with_password_verifier(Arc::new(AcceptPassword));
    let client = client_confidential();
    mgr.register_client_with_secret(client.clone(), "secret")
        .await
        .expect("register");
    let first = mgr
        .password_grant(
            &client.client_id,
            "secret",
            "alice",
            "ok",
            vec!["read".into()],
        )
        .await
        .expect("password grant");
    let old_access = first.access_token.clone();
    mgr.verify_access_token(&old_access)
        .await
        .expect("old valid");
    let refresh = first.refresh_token.expect("refresh");
    let second = mgr
        .refresh_access_token(&refresh, &client.client_id, "secret")
        .await
        .expect("refresh");
    assert_ne!(second.access_token, old_access);
    let old_check = mgr.verify_access_token(&old_access).await;
    assert!(
        old_check.is_err(),
        "old access must fail verify after refresh: {old_check:?}"
    );
}

#[tokio::test]
async fn test_redirect_uri_exact_match() {
    let mgr = OAuth2Manager::new(setup::memory_storage());
    let client = client_confidential();
    assert!(mgr.validate_redirect_uri(&client, "https://app.example/cb"));
    assert!(!mgr.validate_redirect_uri(&client, "https://app.example/cb/extra"));
    assert!(!mgr.validate_redirect_uri(&client, "https://evil.example/cb"));
}
