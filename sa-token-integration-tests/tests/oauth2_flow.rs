//! P2: OAuth2 authorization code flow integration tests.
//!
//! Tests the complete OAuth2 lifecycle: client registration, authorization code
//! generation/exchange, token verification, refresh, revocation, and all error paths.

mod common;

use sa_token_core::{OAuth2Client, OAuth2Manager, SaTokenError, TokenIssueRequest};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

struct AcceptAnyPassword;

#[async_trait::async_trait]
impl sa_token_core::PasswordVerifier for AcceptAnyPassword {
    async fn verify_password(
        &self,
        _username: &str,
        _password: &str,
    ) -> sa_token_core::SaTokenResult<()> {
        Ok(())
    }
}

fn oauth2_mgr() -> OAuth2Manager {
    OAuth2Manager::new(Arc::new(MemoryStorage::new()))
        .with_password_verifier(Arc::new(AcceptAnyPassword))
}

fn test_client() -> OAuth2Client {
    OAuth2Client {
        client_id: "app_001".to_string(),
        client_secret: "secret_001".to_string(),
        client_secret_hash: String::new(),
        public_client: false,
        redirect_uris: vec!["http://localhost:3000/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        scope: vec!["read".to_string(), "write".to_string()],
    }
}

async fn register_test_client(mgr: &OAuth2Manager) {
    mgr.register_client(&test_client())
        .await
        .expect("register client");
}

// ── Success cases: client management ───────────────────────────────────────

#[tokio::test]
async fn test_register_and_get_client() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let client = mgr.get_client("app_001").await.expect("get client");
    assert_eq!(client.client_id, "app_001");
    assert!(!client.client_secret_hash.is_empty());
    assert!(client.client_secret.is_empty());
    assert_eq!(client.redirect_uris, vec!["http://localhost:3000/callback"]);
}

#[tokio::test]
async fn test_verify_client_valid_credentials() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let valid = mgr
        .verify_client("app_001", "secret_001")
        .await
        .expect("verify");
    assert!(valid, "correct credentials should be valid");
}

#[tokio::test]
async fn test_validate_redirect_uri() {
    let mgr = oauth2_mgr();
    let client = test_client();
    assert!(mgr.validate_redirect_uri(&client, "http://localhost:3000/callback"));
    assert!(!mgr.validate_redirect_uri(&client, "http://evil.com/callback"));
}

#[tokio::test]
async fn test_validate_scope_all_permitted() {
    let mgr = oauth2_mgr();
    let client = test_client();
    assert!(mgr.validate_scope(&client, &["read".to_string()]));
    assert!(mgr.validate_scope(&client, &["read".to_string(), "write".to_string()]));
    assert!(!mgr.validate_scope(&client, &["delete".to_string()]));
}

// ── Success cases: authorization code flow ─────────────────────────────────

#[tokio::test]
async fn test_generate_authorization_code() {
    let mgr = oauth2_mgr();
    let code = mgr.generate_authorization_code(
        "app_001".into(),
        "user_42".into(),
        "http://localhost:3000/callback".into(),
        vec!["read".into()],
        None,
        None,
    );
    assert!(code.code.starts_with("code_"));
    assert_eq!(code.client_id, "app_001");
    assert_eq!(code.user_id, "user_42");
    assert_eq!(code.redirect_uri, "http://localhost:3000/callback");
    assert_eq!(code.scope, vec!["read"]);
    assert!(code.expires_at > code.created_at);
}

#[tokio::test]
async fn test_store_and_retrieve_authorization_code() {
    let mgr = oauth2_mgr();
    let code = mgr.generate_authorization_code(
        "app_001".into(),
        "user_1".into(),
        "http://localhost:3000/callback".into(),
        vec!["read".into()],
        None,
        None,
    );
    mgr.store_authorization_code(&code).await.expect("store");
    // Code is stored; consume path uses take_string (no separate get API).
    // 授权码已存储；消费路径走 take_string（无独立 get API）。
    assert!(code.code.starts_with("code_"));
    assert_eq!(code.user_id, "user_1");
}

#[tokio::test]
async fn test_exchange_code_for_token_full_flow() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let code = mgr.generate_authorization_code(
        "app_001".into(),
        "user_full".into(),
        "http://localhost:3000/callback".into(),
        vec!["read".into()],
        None,
        None,
    );
    mgr.store_authorization_code(&code).await.expect("store");

    let token = mgr
        .exchange_code_for_token(
            &code.code,
            "app_001",
            "secret_001",
            "http://localhost:3000/callback",
            None,
        )
        .await
        .expect("exchange");

    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.expires_in, 3600);
    assert!(token.refresh_token.is_some());
    assert!(!token.access_token.is_empty());
}

#[tokio::test]
async fn test_verify_access_token_after_exchange() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let code = mgr.generate_authorization_code(
        "app_001".into(),
        "user_verify".into(),
        "http://localhost:3000/callback".into(),
        vec!["read".into()],
        None,
        None,
    );
    mgr.store_authorization_code(&code).await.expect("store");
    let token = mgr
        .exchange_code_for_token(
            &code.code,
            "app_001",
            "secret_001",
            "http://localhost:3000/callback",
            None,
        )
        .await
        .expect("exchange");

    let info = mgr
        .verify_access_token(&token.access_token)
        .await
        .expect("verify");
    assert_eq!(info.user_id, "user_verify");
    assert_eq!(info.client_id, "app_001");
    assert_eq!(info.scope, vec!["read"]);
}

#[tokio::test]
async fn test_refresh_access_token_returns_new_token() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let code = mgr.generate_authorization_code(
        "app_001".into(),
        "user_refresh".into(),
        "http://localhost:3000/callback".into(),
        vec!["read".into()],
        None,
        None,
    );
    mgr.store_authorization_code(&code).await.expect("store");
    let token = mgr
        .exchange_code_for_token(
            &code.code,
            "app_001",
            "secret_001",
            "http://localhost:3000/callback",
            None,
        )
        .await
        .expect("exchange");
    let refresh = token.refresh_token.as_ref().expect("has refresh token");

    let new_token = mgr
        .refresh_access_token(refresh, "app_001", "secret_001")
        .await
        .expect("refresh");

    assert_ne!(
        new_token.access_token, token.access_token,
        "refreshed token must differ"
    );
    assert_eq!(new_token.token_type, "Bearer");
    assert!(new_token.refresh_token.is_some());
    // New access token should be valid
    let info = mgr
        .verify_access_token(&new_token.access_token)
        .await
        .expect("verify new token");
    assert_eq!(info.user_id, "user_refresh");
}

#[tokio::test]
async fn test_revoke_token() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let code = mgr.generate_authorization_code(
        "app_001".into(),
        "user_revoke".into(),
        "http://localhost:3000/callback".into(),
        vec!["read".into()],
        None,
        None,
    );
    mgr.store_authorization_code(&code).await.expect("store");
    let token = mgr
        .exchange_code_for_token(
            &code.code,
            "app_001",
            "secret_001",
            "http://localhost:3000/callback",
            None,
        )
        .await
        .expect("exchange");

    mgr.revoke_token(&token.access_token).await.expect("revoke");

    let result = mgr.verify_access_token(&token.access_token).await;
    assert!(result.is_err(), "revoked token should not verify");
}

// ── Success cases: consume code is one-time use ───────────────────────────

#[tokio::test]
async fn test_authorization_code_cannot_be_exchanged_twice() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let code = mgr.generate_authorization_code(
        "app_001".into(),
        "user_once".into(),
        "http://localhost:3000/callback".into(),
        vec!["read".into()],
        None,
        None,
    );
    mgr.store_authorization_code(&code).await.expect("store");
    // First exchange succeeds
    mgr.exchange_code_for_token(
        &code.code,
        "app_001",
        "secret_001",
        "http://localhost:3000/callback",
        None,
    )
    .await
    .expect("first exchange");
    // Second exchange fails (code consumed/deleted)
    let result = mgr
        .exchange_code_for_token(
            &code.code,
            "app_001",
            "secret_001",
            "http://localhost:3000/callback",
            None,
        )
        .await;
    assert!(result.is_err(), "code reuse must fail");
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::OAuth2CodeNotFound
    ));
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_nonexistent_client() {
    let mgr = oauth2_mgr();
    let result = mgr.get_client("no_such_client").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::OAuth2ClientNotFound
    ));
}

#[tokio::test]
async fn test_verify_client_wrong_secret() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let valid = mgr
        .verify_client("app_001", "wrong_secret")
        .await
        .expect("verify check");
    assert!(!valid, "wrong secret should not verify");
}

#[tokio::test]
async fn test_exchange_code_with_wrong_secret() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let code = mgr.generate_authorization_code(
        "app_001".into(),
        "user_err".into(),
        "http://localhost:3000/callback".into(),
        vec!["read".into()],
        None,
        None,
    );
    mgr.store_authorization_code(&code).await.expect("store");
    let result = mgr
        .exchange_code_for_token(
            &code.code,
            "app_001",
            "wrong_secret",
            "http://localhost:3000/callback",
            None,
        )
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::OAuth2InvalidCredentials
    ));
}

#[tokio::test]
async fn test_exchange_code_wrong_redirect_uri() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let code = mgr.generate_authorization_code(
        "app_001".into(),
        "user_uri".into(),
        "http://localhost:3000/callback".into(), // registered during generation
        vec!["read".into()],
        None,
        None,
    );
    mgr.store_authorization_code(&code).await.expect("store");
    let result = mgr
        .exchange_code_for_token(
            &code.code,
            "app_001",
            "secret_001",
            "http://wrong-uri.com/callback",
            None,
        )
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::OAuth2RedirectUriMismatch
    ));
}

#[tokio::test]
async fn test_exchange_code_wrong_client_id() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    // Register a second client
    let client2 = OAuth2Client {
        client_id: "app_002".into(),
        client_secret: "secret_002".into(),
        client_secret_hash: String::new(),
        public_client: false,
        redirect_uris: vec!["http://localhost:4000/back".into()],
        grant_types: vec!["authorization_code".into()],
        scope: vec!["read".into()],
    };
    mgr.register_client(&client2)
        .await
        .expect("register client2");

    let code = mgr.generate_authorization_code(
        "app_001".into(),
        "user_cid".into(),
        "http://localhost:3000/callback".into(),
        vec!["read".into()],
        None,
        None,
    );
    mgr.store_authorization_code(&code).await.expect("store");
    // Try to exchange with wrong client_id
    let result = mgr
        .exchange_code_for_token(
            &code.code,
            "app_002",
            "secret_002",
            "http://localhost:3000/callback",
            None,
        )
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::OAuth2ClientIdMismatch
    ));
}

#[tokio::test]
async fn test_exchange_nonexistent_code() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let result = mgr
        .exchange_code_for_token(
            "no_such_code",
            "app_001",
            "secret_001",
            "http://localhost:3000/callback",
            None,
        )
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::OAuth2CodeNotFound
    ));
}

#[tokio::test]
async fn test_verify_nonexistent_access_token() {
    let mgr = oauth2_mgr();
    let result = mgr.verify_access_token("no_such_access_token").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::OAuth2AccessTokenNotFound
    ));
}

#[tokio::test]
async fn test_refresh_with_wrong_client_id() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let client2 = OAuth2Client {
        client_id: "app_003".into(),
        client_secret: "secret_003".into(),
        client_secret_hash: String::new(),
        public_client: false,
        redirect_uris: vec!["http://localhost:5000/cb".into()],
        grant_types: vec!["refresh_token".into()],
        scope: vec!["read".into()],
    };
    mgr.register_client(&client2)
        .await
        .expect("register client2");

    let code = mgr.generate_authorization_code(
        "app_001".into(),
        "user_rf".into(),
        "http://localhost:3000/callback".into(),
        vec!["read".into()],
        None,
        None,
    );
    mgr.store_authorization_code(&code).await.expect("store");
    let token = mgr
        .exchange_code_for_token(
            &code.code,
            "app_001",
            "secret_001",
            "http://localhost:3000/callback",
            None,
        )
        .await
        .expect("exchange");
    let refresh = token.refresh_token.as_ref().expect("has refresh");

    // Try to refresh with wrong client
    let result = mgr
        .refresh_access_token(refresh, "app_003", "secret_003")
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::OAuth2ClientIdMismatch
    ));
}

#[tokio::test]
async fn test_refresh_with_nonexistent_token() {
    let mgr = oauth2_mgr();
    register_test_client(&mgr).await;
    let result = mgr
        .refresh_access_token("no_such_refresh", "app_001", "secret_001")
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::OAuth2RefreshTokenNotFound
    ));
}

#[tokio::test]
async fn test_password_grant() {
    let mgr = oauth2_mgr();
    let mut client = test_client();
    client.grant_types.push("password".to_string());
    mgr.register_client(&client).await.expect("register");
    let token = mgr
        .password_grant(
            "app_001",
            "secret_001",
            "user_pwd",
            "any",
            vec!["read".into()],
        )
        .await
        .expect("password grant");
    let info = mgr
        .verify_access_token(&token.access_token)
        .await
        .expect("verify");
    assert_eq!(info.user_id, "user_pwd");
}

#[tokio::test]
async fn test_client_credentials_grant() {
    let mgr = oauth2_mgr();
    let mut client = test_client();
    client.grant_types.push("client_credentials".to_string());
    mgr.register_client(&client).await.expect("register");
    let token = mgr
        .client_credentials_grant("app_001", "secret_001", vec!["read".into()])
        .await
        .expect("client_credentials");
    let info = mgr
        .verify_access_token(&token.access_token)
        .await
        .expect("verify");
    assert_eq!(info.user_id, "client:app_001");
}

#[tokio::test]
async fn test_issue_token_dispatches_grants() {
    let mgr = oauth2_mgr();
    let mut client = test_client();
    client.grant_types = vec![
        "authorization_code".into(),
        "refresh_token".into(),
        "password".into(),
        "client_credentials".into(),
    ];
    mgr.register_client(&client).await.expect("register");

    let cc = mgr
        .issue_token(TokenIssueRequest {
            grant_type: "client_credentials".into(),
            client_id: "app_001".into(),
            client_secret: "secret_001".into(),
            scope: vec!["read".into()],
            ..Default::default()
        })
        .await
        .expect("issue client_credentials");
    assert!(!cc.access_token.is_empty());

    let pwd = mgr
        .issue_token(TokenIssueRequest {
            grant_type: "password".into(),
            client_id: "app_001".into(),
            client_secret: "secret_001".into(),
            username: Some("user_x".into()),
            password: Some("pwd".into()),
            scope: vec!["read".into()],
            ..Default::default()
        })
        .await
        .expect("issue password");
    assert!(!pwd.access_token.is_empty());
}
