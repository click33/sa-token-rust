# OAuth2

English | [中文](/zh/guide/oauth2.md)

`OAuth2Manager` covers authorization-code, refresh, password, and client-credentials flows. State is persisted through `SaTokenDao`. You can share Dao / key prefix with an existing `SaTokenManager`.

## When to use

- You run an authorization server that issues access / refresh tokens.
- Public clients need PKCE.
- Password grant: you implement `PasswordVerifier`; core never stores user passwords.

## Create the manager

```rust
use sa_token_core::oauth2::OAuth2Manager;
use sa_token_core::SaTokenManager;

// Align Dao with an existing Manager (recommended)
let oauth = OAuth2Manager::from_manager(&manager)
    .with_ttl(600, 3600, 2_592_000) // code / access / refresh (seconds)
    .with_require_pkce(false);

// Or OAuth2Manager::from_dao(dao) / OAuth2Manager::new(storage)
```

## Register a client

Secrets are stored as Argon2 PHC. At registration you may set plaintext `client_secret` (in-memory only, not serialized) or a ready `client_secret_hash`.

```rust
use sa_token_core::oauth2::OAuth2Client;

let client = OAuth2Client {
    client_id: "web-app".into(),
    client_secret: "plain-secret-at-register".into(),
    client_secret_hash: String::new(),
    redirect_uris: vec!["https://app.example/callback".into()],
    grant_types: vec![
        "authorization_code".into(),
        "refresh_token".into(),
    ],
    scope: vec!["openid".into(), "profile".into()],
    public_client: false,
};
oauth.register_client(&client).await?;
// or register_client_with_secret(client_id, plain_secret, ...)
```

Public clients: `public_client = true`, no secret; authorization-code **requires** PKCE.

## Authorization code + PKCE

```rust
use sa_token_core::oauth2::{PkceChallenge, TokenIssueRequest};

let pkce = PkceChallenge::from_verifier_s256(&code_verifier)?;
let code = oauth
    .issue_authorization_code(
        "web-app".into(),
        "user_42".into(),
        "https://app.example/callback".into(),
        vec!["openid".into()],
        Some(pkce),
        Some("state-xyz".into()),
    )
    .await?;

let token = oauth
    .issue_token(TokenIssueRequest {
        grant_type: "authorization_code".into(),
        client_id: "web-app".into(),
        client_secret: "plain-secret-at-register".into(),
        code: Some(code.code),
        redirect_uri: Some("https://app.example/callback".into()),
        code_verifier: Some(code_verifier),
        ..Default::default()
    })
    .await?;
```

You can also call `exchange_code_for_token`, `refresh_access_token`, and `revoke_token`. `issue_token` dispatches by `grant_type`.

## Password grant

Implement `PasswordVerifier` and attach it:

```rust
use async_trait::async_trait;
use sa_token_core::oauth2::PasswordVerifier;
use sa_token_core::{SaTokenError, SaTokenResult};
use std::sync::Arc;

struct MyVerifier;

#[async_trait]
impl PasswordVerifier for MyVerifier {
    async fn verify_password(&self, username: &str, password: &str) -> SaTokenResult<()> {
        if username == "alice" && password == "correct" {
            Ok(())
        } else {
            Err(SaTokenError::OAuth2InvalidCredentials)
        }
    }
}

let oauth = OAuth2Manager::from_manager(&manager)
    .with_password_verifier(Arc::new(MyVerifier));

let token = oauth
    .issue_token(TokenIssueRequest {
        grant_type: "password".into(),
        client_id: "web-app".into(),
        client_secret: "plain-secret-at-register".into(),
        username: Some("alice".into()),
        password: Some("correct".into()),
        scope: vec!["profile".into()],
        ..Default::default()
    })
    .await?;
```

Also available: `client_credentials_grant` / `grant_type: "client_credentials"`.

## Verify and revoke

```rust
let info = oauth.verify_access_token(&token.access_token).await?;
oauth.revoke_token(&token.access_token).await?;
```

## Pitfalls

| Topic | Note |
|-------|------|
| Dao | Prefer `from_manager` / `from_dao` so keys stay aligned |
| PKCE | Required for public clients; `with_require_pkce(true)` forces it for confidential clients too |
| Secrets | Storage keeps hashes; use `verify_client` for checks |

## Related

- [SSO](/guide/sso.md)
- [Security features](/guide/security-features.md)
- [Error reference](/reference/error-reference.md)
