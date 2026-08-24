# SSO (single sign-on)

English | [中文](/zh/guide/sso.md)

`SsoServer` issues tickets and coordinates logout; `SsoClient` exchanges tickets for a local login; `SsoManager` holds config plus both sides. Tickets and sessions are Dao-backed.

## Config

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

## Server: SsoServer

```rust
use sa_token_core::sso::SsoServer;
use std::sync::Arc;

let server = SsoServer::new(Arc::new(manager)).with_config(&cfg);

// After login, issue a ticket
let ticket = server.create_ticket("user_1".into(), "https://app.example".into()).await?;
// or server.login(login_id, service).await?

// Client validates the ticket
let login_id = server.validate_ticket(&ticket.ticket_id, "https://app.example").await?;

// Unified logout: clear SSO session and return client URLs to notify
let logout_urls = server.logout_with_slo("user_1").await?;
```

Default SLO notifier is `NoopSloNotifier`. For HTTP callbacks, enable the feature and use `HttpSloNotifier` (below).

## Client: SsoClient

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

`LocalTicketChecker` fits in-process or direct Server access. Use `sso-http` for remote validation.

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

## Feature: `sso-http`

Enable on `sa-token-core`:

```toml
sa-token-core = { version = "0.2.0", features = ["sso-http"] }
```

Provides:

- `HttpTicketChecker` — signed remote ticket checks
- `HttpSloNotifier` — HTTP POST form logout notifications

Without the feature you still have the local checker and `NoopSloNotifier`.

## Tickets and SLO (brief)

- Ticket: short-lived, one-time; `create_ticket` persists via Dao; `validate_ticket` / `check_ticket` consume it.
- SSO session: tracks client URLs where the user is logged in.
- SLO: `logout_with_slo` clears the session and builds notify URLs; delivery depends on `SloNotifier`.

## Related

- [OAuth2](/guide/oauth2.md)
- [Security features](/guide/security-features.md) (request signing)
- [Error reference](/reference/error-reference.md)
