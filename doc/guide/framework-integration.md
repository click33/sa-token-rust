# Framework integration

English | [中文](/zh/guide/framework-integration.md)

Web plugins share `SaTokenState` from `sa-token-plugin-common`. Middleware uses the same `run_auth_flow`. Token reading goes through core `token_io` (header / cookie / body + optional `token_prefix`).

## SaTokenState

```rust
use sa_token_plugin_axum::*; // or another plugin facade
use std::sync::Arc;

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_name("Authorization")
    .timeout(86400)
    .is_read_header(true)
    .build(); // try_init_manager inside; library code may use SaTokenConfig::try_build
```

Do not depend on removed `sa-token-plugin-*-core` crates.

## Axum: Layer + Extractor

```rust
use axum::{Router, routing::{get, post}};
use sa_token_plugin_axum::*;

let path_auth = PathAuthConfig::new()
    .include(vec!["/**".into()])
    .exclude(vec!["/api/login".into(), "/api/health".into()]);

let app = Router::new()
    .route("/api/login", post(login))
    .route("/api/me", get(me))
    .layer(SaTokenLayer::with_path_auth(state.clone(), path_auth))
    .with_state(state);

async fn me(SaTokenExtractor(token): SaTokenExtractor) -> String {
    token.as_str().to_string()
}
// Also: OptionalSaTokenExtractor, LoginIdExtractor
```

Public routes must use `PathAuthConfig::exclude`. `#[sa_ignore]` skips macro checks only — not the Layer.

## Actix-web: Middleware

The facade defaults to **`v4`**. Feature **`v5` is a placeholder only**; enabling it alone triggers `compile_error!`. Use `v4` in production.

```toml
sa-token-plugin-actix-web = "0.2.0" # default features include v4
```

```rust
use actix_web::{App, HttpServer, web};
use sa_token_plugin_actix_web::*;

HttpServer::new(move || {
    App::new()
        .app_data(web::Data::new(state.clone()))
        .wrap(SaTokenMiddleware::with_path_auth(
            state.clone(),
            PathAuthConfig::new()
                .include(vec!["/**".into()])
                .exclude(vec!["/api/login".into()]),
        ))
        .route("/api/login", web::post().to(login))
})
```

## Other plugins (short table)

| Framework | Crate | Notes |
|-----------|-------|-------|
| Poem | `sa-token-plugin-poem` | `SaTokenLayer::with_path_auth` |
| Warp | `sa-token-plugin-warp` | All-in-one |
| Tide | `sa-token-plugin-tide` | All-in-one |
| Rocket | `sa-token-plugin-rocket` | Facade; pick major via feature |
| Salvo | `sa-token-plugin-salvo` | Facade |
| Gotham | `sa-token-plugin-gotham` | Facade |
| Ntex | `sa-token-plugin-ntex` | Facade |
| Tonic | `sa-token-plugin-tonic` | gRPC Layer + PathAuth |

## Token reading (token_io)

Adapters map the request to `SaRequest`, then:

- `token_io::read_token` — respects `is_read_header` / `is_read_cookie` / `is_read_body` and `token_name`
- `apply_token_prefix` — optional prefix
- Write-back: `is_write_cookie` + `write_token_cookie`

Map-shaped handshake reads use `read_token_from_maps` ([WebSocket auth](/guide/websocket-auth.md)).

## Related

- [Quick start](/guide/quick-start.md)
- [Path auth](/guide/path-auth.md)
- [Adapter](/guide/adapter.md)
