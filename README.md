# sa-token-rust

[简体中文](README_zh-CN.md) | English

Lightweight authentication and authorization for Rust. Inspired by the Dromara sa-token project; this tree is an independent implementation (MIT OR Apache-2.0). See [NOTICE](NOTICE).

It targets Web and gRPC: the same `StpUtil` / `SaTokenState` model works across Axum, Actix-web, Poem, Rocket, Warp, Salvo, Tide, Gotham, Ntex, and Tonic.

Guides: [doc/index.md](doc/index.md). Upgrading from 0.1.x: [MIGRATION_0.2.md](MIGRATION_0.2.md).

## What you can do

Login, logout, kick-out, and replace flows are orchestrated by `AuthService`. Application code usually calls the static façade: `StpUtil::login`, `logout`, `kick_out`. Example: `let token = StpUtil::login("10001").await?;`

Permissions and roles go through `AuthzService`. Use `has_permission` / `check_role` in code, or attach macros such as `#[sa_check_permission("user:add")]`. Wildcard vs exact matching is documented in the permissions guide.

Path-level middleware auth uses `PathAuthConfig`. Public routes must be listed in `exclude`. `#[sa_ignore]` only skips macro-inserted checks; it does **not** bypass the Layer or middleware.

Memory, Redis, and Database backends go through `SaTokenDao`. Switch backends with plugin Cargo features; key layout is owned by `SaKeys`.

JWT, nonce, refresh tokens, OAuth2 (with PKCE), SSO, WebSocket auth, online presence, distributed sessions, and the event bus each have dedicated guides.

Multi-account isolation uses `login_type`, for example admin vs user: `StpUtil::builder("42").login_type("admin").device("pc").login(None).await?`.

## Install

```toml
[dependencies]
sa-token-plugin-axum = "0.2.0"
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

Redis:

```toml
sa-token-plugin-axum = { version = "0.2.0", features = ["redis"] }
```

One import: `use sa_token_plugin_axum::*;`

Other plugins: `sa-token-plugin-{actix-web,poem,rocket,warp,salvo,tide,gotham,ntex,tonic}`. Actix-web / Rocket / Salvo / Ntex / Gotham are façade crates (defaults such as `v4`, `v05`). The Actix `v5` feature is a placeholder — use `v4` in production.

`SaTokenState::builder().build()` panics if `storage` is missing. Libraries should use `SaTokenConfig::builder().try_build()` and handle `Result`.

## Minimal example

```rust
use std::sync::Arc;
use axum::{routing::get, Router};
use sa_token_plugin_axum::*;
use sa_token_core::router::PathAuthConfig;

#[sa_check_login]
async fn me() -> SaTokenResult<&'static str> {
    Ok("ok")
}

async fn health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .timeout(86400)
        .build();

    let path_auth = PathAuthConfig::new()
        .include(vec!["/**".into()])
        .exclude(vec!["/health".into()]);

    let app = Router::new()
        .route("/health", get(health))
        .route("/me", get(me))
        .layer(SaTokenLayer::with_path_auth(state, path_auth));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

Login: `StpUtil::login("user_10001").await?`.

## Initialization

`SaTokenState::build()` attempts `StpUtil::try_init_manager` once. A second call returns `AlreadyInitialized` and does not replace the global manager.

Prefer this in libraries and tests:

```rust
let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(7200)
    .try_build()?;
```

Optional prefix: `.token_prefix("Bearer ")`. Optional cookie writes: `.is_write_cookie(true)` plus `write_token_cookie` on the response path.

## Documentation

Canonical guides live under VitePress `doc/`:

- [Quick start](doc/guide/quick-start.md)
- [StpUtil](doc/guide/stp-util.md)
- [Path auth](doc/guide/path-auth.md)
- [Permissions and macros](doc/guide/permission-matching.md)
- [Storage](doc/guide/storage.md)
- [Migrate to 0.2](doc/guide/migration-0.2.md)

More topics: [doc/index.md](doc/index.md). Files under `docs/` are compatibility stubs only.

## Examples

See `examples/`: `axum-full-example`, `actix-web-example`, `path_auth_example.rs`, `jwt_example.rs`, `sso_example.rs`, `oauth2_example.rs`, `websocket_online_example.rs`, and others.

## Contributing and license

Issues: https://github.com/sa-tokens/sa-token-rust/issues

MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
