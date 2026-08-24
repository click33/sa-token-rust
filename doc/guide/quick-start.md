# Quick start

[中文](/zh/guide/quick-start.md)

Get sa-token-rust running on an Axum service in a few minutes. This page covers dependencies, initialization, path auth, login, and where to go next.

## Add a dependency

Prefer a single framework plugin crate (it re-exports core types and macros):

```toml
[dependencies]
sa-token-plugin-axum = "0.2.0"
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

One import:

```rust
use sa_token_plugin_axum::*;
```

### Storage features

| Feature | Notes |
|---------|--------|
| `memory` | Default; in-process storage |
| `redis` | Redis backend |
| `database` | Database backend (basic KV; see [Storage](/guide/storage.md) for limits) |
| `full` | All of the above |

```toml
sa-token-plugin-axum = { version = "0.2.0", features = ["redis"] }
```

### Choosing a plugin

| Crate | Notes |
|-------|--------|
| `sa-token-plugin-axum` | All-in-one; default `axum-08` + `memory` |
| `sa-token-plugin-poem` / `warp` / `tide` | All-in-one |
| `sa-token-plugin-actix-web` | Facade; default `v4`. The `v5` feature is a placeholder — use `v4` in production |
| `sa-token-plugin-rocket` / `salvo` / `gotham` / `ntex` | Facades; pick the major version via features |
| `sa-token-plugin-tonic` | gRPC |

`SaTokenState` lives in `sa-token-plugin-common` and is re-exported by each plugin. Do not depend on removed `*-core` crates.

For fine-grained control you can pull in `sa-token-core` and `sa-token-storage-memory` explicitly; most apps only need the plugin import.

## Minimal runnable example

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

Notes:

- `SaTokenState::builder().build()` attempts `StpUtil::try_init_manager`. Missing `storage` panics.
- Public routes must be listed in `PathAuthConfig::exclude`. `#[sa_ignore]` does **not** bypass middleware.
- Protected handlers can keep using `#[sa_check_login]` / `#[sa_check_permission(...)]` for declarative checks.

## Login and logout

Once initialized:

```rust
let token = StpUtil::login("user_10001").await?;
StpUtil::logout(&token).await?;
```

Clients send the token via header (or cookie / query, depending on `is_read_*`). The key name is `token_name` (default `"sa-token"`). Optional prefix:

```rust
SaTokenConfig::builder()
    .storage(storage)
    .token_prefix("Bearer ")
    .try_build()?;
```

To write a cookie after login, enable `.is_write_cookie(true)` and call `write_token_cookie` on the response path (see `token_io`). Cookie writes are off by default.

## Libraries: prefer `try_build`

`SaTokenState` is convenient at application startup. In libraries, tests, or anywhere you want an explicit `Result`:

```rust
use std::sync::Arc;
use sa_token_core::SaTokenConfig;
use sa_token_storage_memory::MemoryStorage;

let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(7200)
    .auto_renew(false) // false is already the 0.2 default
    .try_build()?;

StpUtil::try_init_manager(manager)?;
```

`try_build` returns `Err(SaTokenError::ConfigError)` for missing storage or invalid JWT secrets instead of panicking on a library path. A second `try_init_manager` returns `AlreadyInitialized` and does not replace the global manager.

## Next steps

- [StpUtil](/guide/stp-util.md) — login state, permissions, session APIs
- [Path auth](/guide/path-auth.md) — `include` / `exclude` / validators
- [Framework integration](/guide/framework-integration.md) — Web / gRPC plugin matrix
- [Migrate to 0.2](/guide/migration-0.2.md) — upgrading from 0.1.x
- Repository `examples/` — `axum-full-example`, `actix-web-example`, and more
