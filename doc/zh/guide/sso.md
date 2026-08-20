# SSO 单点登录

[English](/guide/sso.md) | 中文

`SsoServer` 发票据与统一登出；`SsoClient` 换票并建立本地登录；`SsoManager` 组合配置与两端；票据与会话经 Dao 持久化。

## 配置

```rust
use sa_token_core::sso::SsoConfig;

let cfg = SsoConfig::builder()
    .server_url("https://sso.example/sso")
    .ticket_timeout(300)
    .allow_cross_domain(true)
    .allowed_origins(vec!["https://app.example".into()])
    .sign_secret("sso-hmac-secret")
    .sign_window_secs(300)
    .build();
```

## 服务端 SsoServer

```rust
use sa_token_core::sso::SsoServer;
use std::sync::Arc;

let server = SsoServer::new(Arc::new(manager)).with_config(&cfg);

// 登录成功后发 ticket
let ticket = server.create_ticket("user_1".into(), "https://app.example".into()).await?;
// 或 server.login(login_id, service).await?

// 客户端来验票
let login_id = server.validate_ticket(&ticket.ticket_id, "https://app.example").await?;

// 统一登出：清 SSO 会话并返回需通知的客户端 URL
let logout_urls = server.logout_with_slo("user_1").await?;
```

默认 SLO 通知器为 `NoopSloNotifier`。需要 HTTP 回调时启用 feature 并换 `HttpSloNotifier`（见下）。

## 客户端 SsoClient

```rust
use sa_token_core::sso::{LocalTicketChecker, SsoClient};
use std::sync::Arc;

let client = SsoClient::new(
    Arc::new(manager.clone()),
    "https://sso.example/sso".into(),
    "https://app.example".into(),
)
.with_ticket_checker(Arc::new(LocalTicketChecker {
    store: sa_token_core::sso::SsoTicketStore::new(manager.dao().clone(), cfg.ticket_timeout),
}));

let login_url = client.get_login_url();
let login_id = client.process_ticket(&ticket_id, "https://app.example").await?;
let local_token = client.login_by_ticket(login_id).await?;
client.handle_logout("user_1").await?;
```

`LocalTicketChecker` 适合同进程或可直连 Server 的场景。跨网络验票用 `sso-http`。

## SsoManager

```rust
use sa_token_core::sso::SsoManager;

let sso = SsoManager::new(cfg)
    .with_server(Arc::new(server))
    .with_client(Arc::new(client));

let _ = sso.server();
let _ = sso.client();
sso.is_allowed_origin("https://app.example");
```

## Feature：`sso-http`

在 `sa-token-core` 上启用：

```toml
sa-token-core = { version = "0.2.0", features = ["sso-http"] }
```

提供：

- `HttpTicketChecker`：带签名的远程验票
- `HttpSloNotifier`：HTTP POST 表单通知各客户端登出

未启用时仍可用本地 checker / `NoopSloNotifier`。

## 票据与 SLO（简述）

- Ticket：短期、一次性；`create_ticket` 写入 Dao，`validate_ticket` / `check_ticket` 消费。
- SSO Session：记录用户已登录的客户端 URL 列表。
- SLO：`logout_with_slo` 删会话并生成通知 URL；实际推送取决于 `SloNotifier`。

## 相关链接

- [OAuth2](/zh/guide/oauth2.md)
- [安全特性](/zh/guide/security-features.md)（请求签名）
- [错误参考](/zh/reference/error-reference.md)
