# sa-token-plugin-common

Shared plugin primitives: `SaTokenState`, JSON rejection helpers, `CapturedRequest`.
This crate has **no** dependency on Axum/Actix/etc.

```toml
[dependencies]
sa-token-plugin-common = "0.2.0"
```

```rust
use sa_token_plugin_common::SaTokenState;
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(7200)
    .build();
```

Framework crates re-export these types. You usually depend on `sa-token-plugin-axum` (or another plugin) only.
