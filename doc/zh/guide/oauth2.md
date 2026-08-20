# OAuth2

[English](/guide/oauth2.md) | 中文

`OAuth2Manager` 提供授权码、刷新、密码、客户端凭证等协议能力，状态经 `SaTokenDao` 持久化。可与现有 `SaTokenManager` 共享 Dao / 键前缀。

## 何时使用

- 自建授权服务器，给第三方发 access / refresh token。
- 公共客户端需要 PKCE。
- 密码模式：由你实现 `PasswordVerifier`，core 不存用户密码。

## 创建 Manager

```rust
use sa_token_core::oauth2::OAuth2Manager;
use sa_token_core::SaTokenManager;

// 与现有 Manager 对齐 Dao（推荐）
let oauth = OAuth2Manager::from_manager(&manager)
    .with_ttl(600, 3600, 2_592_000) // code / access / refresh（秒）
    .with_require_pkce(false);

// 或 OAuth2Manager::from_dao(dao) / OAuth2Manager::new(storage)
```

## 注册客户端

密钥以 Argon2 PHC 形式存储。注册时可用明文 `client_secret`（仅内存字段，不序列化），或已哈希的 `client_secret_hash`。

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
// 或 register_client_with_secret(client_id, plain_secret, ...)
```

公共客户端：`public_client = true`，无密钥，授权码流程 **必须** 带 PKCE。

## 授权码 + PKCE

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

也可用 `exchange_code_for_token` / `refresh_access_token` / `revoke_token`。`issue_token` 按 `grant_type` 分发。

## 密码模式

实现 `PasswordVerifier`，挂到 Manager：

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

另有 `client_credentials_grant` / `grant_type: "client_credentials"`。

## 校验与吊销

```rust
let info = oauth.verify_access_token(&token.access_token).await?;
oauth.revoke_token(&token.access_token).await?;
```

## 陷阱

| 点 | 说明 |
|----|------|
| Dao | 生产与业务 Manager 共用 `from_manager` / `from_dao`，避免双键空间 |
| PKCE | 公共客户端强制；`with_require_pkce(true)` 可对机密客户端也强制 |
| 密钥 | 存储的是 hash；校验用 `verify_client` |

## 相关链接

- [SSO](/zh/guide/sso.md)
- [安全特性](/zh/guide/security-features.md)
- [错误参考](/zh/reference/error-reference.md)
