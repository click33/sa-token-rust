# sa-token-core

Core authentication and authorization library for sa-token-rust (0.2.0).

## Features

- Token / session / grants via `AuthService` and `AuthzService`
- Storage funnel `SaTokenDao` + key schema `SaKeys`
- JWT, nonce, refresh token, OAuth2 + PKCE, SSO, online presence
- Event bus with `DispatchMode::{Sequential, Concurrent, Detached}`
- `StpUtil::try_init_manager` (prefer over deprecated `init_manager`)

## Installation

```toml
[dependencies]
sa-token-core = "0.2.0"
sa-token-adapter = "0.2.0"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use sa_token_core::SaTokenConfig;
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let manager = SaTokenConfig::builder()
    .storage(storage)
    .timeout(7200)
    .token_name("satoken")
    .try_build()?;
let token = manager.login("user_123").await?;
let ok = manager.is_valid(&token).await;
manager.logout(&token).await?;
```

### JWT

```rust
use sa_token_core::{SaTokenConfig, TokenStyle};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_style(TokenStyle::Jwt)
    .jwt_secret_key("your-secret-key")
    .try_build()?;
```

### Event Listeners

```rust
use sa_token_core::event::SaTokenListener;
use async_trait::async_trait;
use std::sync::Arc;

struct MyListener;

#[async_trait]
impl SaTokenListener for MyListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }
}
```

## Documentation

- Guides: [doc/guide](../doc/guide/quick-start.md)
- Migration: [MIGRATION_0.2.md](../MIGRATION_0.2.md)

## License

MIT OR Apache-2.0
