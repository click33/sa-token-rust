# Storage Backends

[中文](/zh/guide/storage.md) | English

Tokens, sessions, and permission caches all land on `SaStorage`. Version 0.2 ships Memory, Redis, and Database (PostgreSQL) backends. Application code should go through `SaTokenDao`, not hold raw storage in services.

## Plugin features

Enable the matching feature on a framework plugin (for example `sa-token-plugin-axum`) to re-export the storage type:

| Feature | Crate | Notes |
|---------|-------|-------|
| `memory` (default) | `sa-token-storage-memory` | In-process |
| `redis` | `sa-token-storage-redis` | Redis |
| `database` | `sa-token-storage-database` | Relational KV (default `postgres`) |
| `full` | all of the above | Enable together |

```toml
sa-token-plugin-axum = { version = "0.2.0", features = ["redis"] }
# or depend on the storage crate directly
# sa-token-storage-redis = "0.2.0"
```

## Inject into the builder

Wrap every backend as `Arc<dyn SaStorage>` (or `Arc` of a concrete type) and pass it to the builder:

```rust
use std::sync::Arc;
use sa_token_plugin_axum::*; // or MemoryStorage / RedisStorage / DatabaseStorage

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(86400)
    .build();
```

For libraries, prefer `SaTokenConfig::builder().storage(...).try_build()?` then `StpUtil::try_init_manager`.

## SaTokenDao

`SaTokenManager` uses `SaTokenDao` as the single storage funnel: key layout (`SaKeys`), serialization, and TTL live there. Repositories and services **must not** hold `SaStorage` directly. Most apps only pick a backend and inject it; dig into `SaTokenDao` when you need custom keys or atomic primitives.

---

## Pluggable serialization (`SaSerializer`)

Domain objects written to storage (token info, sessions, nonce records, OAuth2/SSO payloads, and so on) go through a pluggable serializer on `SaTokenConfig`. Call sites should use `SharedSerializer` (a Clone-friendly enum). The default is JSON; optional binary encoding is available behind the `fory` feature.

### Defaults and when to switch

| Choice | When |
|--------|------|
| **JSON** (default) | Compatible with existing 0.1 / early 0.2 data; human-readable in Redis CLI |
| **fory** (`feature = "fory"`) | Smaller payloads / less Redis string noise; rolling upgrade still reads legacy JSON |

You do **not** need to change anything for a normal install: omit `.serializer(...)` and keep JSON.

### Inject via builder

Types are re-exported from `sa-token-core` (and from the root `sa-token` / plugin crates when features allow):

```rust
use sa_token_adapter::{JsonSerializer, JsonSerializerConfig};
use sa_token_core::{SaTokenConfig, SharedSerializer};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

// Default JSON — explicit form
let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .serializer(SharedSerializer::Json(JsonSerializer::default()))
    .try_build()?;

// Pretty JSON for local debugging only (do not use in production)
let debug = SharedSerializer::Json(JsonSerializer::with_config(JsonSerializerConfig {
    pretty_print: true,
    ..Default::default()
}));
```

### Optional fory (binary)

Enable the feature on the crate you depend on:

```toml
# root meta-crate
sa-token = { version = "0.2.0", features = ["fory"] }

# or core / adapter directly
sa-token-core = { version = "0.2.0", features = ["fory"] }
```

```rust
#[cfg(feature = "fory")]
use sa_token_core::{ForySerializer, SaTokenConfig, SharedSerializer};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[cfg(feature = "fory")]
let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .serializer(SharedSerializer::from(ForySerializer::default()))
    .try_build()?;
```

Binary string payloads are prefixed with magic `\u{0001}STF` (`BINARY_MAGIC`) so the read path can tell formats apart.

### Rolling upgrade semantics

| Active serializer | Reading legacy pure JSON | Reading magic-prefixed binary |
|-------------------|--------------------------|-------------------------------|
| JSON | OK | `FormatMismatch` → surfaces as `SaTokenError::SerializationError` |
| fory | OK (legacy path) | OK |

Practical rollout: keep writing JSON until all nodes can enable `fory`, then switch writers; leave fory readers on until old JSON rows expire or are rewritten. Switching **back** to JSON while binary rows remain will fail decode with a format mismatch — migrate or wait for TTL first.

### Errors

`SerializerError` (`EncodeFailed` / `DecodeFailed` / `FormatMismatch` / `VersionIncompatible`) maps into `SaTokenError::SerializationError(String)` via `Display`. See [Error reference](../reference/error-reference.md).

### Trait overview

`SaSerializer` exposes `name` / `kind` / `encode` / `decode`, plus optional `encode_bytes` / `decode_bytes`. Prefer configuring through `SaTokenConfigBuilder::serializer`; application code rarely calls the trait directly.

---

## MemoryStorage

Best for development, tests, and single-process non-persistent setups.

```rust
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
// optional: sweep expired entries
storage.cleanup_expired().await;
```

Fast and dependency-free; data is lost on restart and is not shared across processes.

---

## RedisStorage

For production and multi-instance shared sessions. Common constructors:

```rust
use sa_token_storage_redis::{RedisStorage, RedisConfig};
use std::sync::Arc;

// 1) URL + key prefix
let storage = RedisStorage::new(
    "redis://:password@localhost:6379/0",
    "sa-token:",
).await?;

// 2) Convenience: empty physical prefix (logical keys come from SaKeys)
let storage = RedisStorage::connect("redis://localhost:6379/0").await?;

// 3) Config struct
let storage = RedisStorage::from_config(
    RedisConfig {
        host: "localhost".into(),
        port: 6379,
        password: Some("password".into()),
        database: 0,
        ..Default::default()
    },
    "sa-token:",
).await?;

let state = SaTokenState::builder()
    .storage(Arc::new(storage))
    .build();
```

You can also use `RedisStorage::builder().host(...).port(...).key_prefix(...).build().await?`.

URL examples: `redis://localhost:6379/0`, `redis://:mypass@localhost:6379/0`.

---

## DatabaseStorage

sqlx-based PostgreSQL KV storage. The crate’s default feature is `postgres`:

```toml
sa-token-storage-database = "0.2.0"
# equivalent to features = ["postgres"]
```

```rust
use sa_token_storage_database::DatabaseStorage;
use std::sync::Arc;

let storage = DatabaseStorage::new("postgres://user:pass@localhost/db").await?;
// or DatabaseStorage::from_pool(pool)

let state = SaTokenState::builder()
    .storage(Arc::new(storage))
    .build();
```

`new` connects and runs the embedded DDL (idempotent). Basic KV (`get` / `set` / `delete`, …) is supported; `get_del`, CAS, `list_*`, and `scan` return `StorageError::Unsupported`. Use Memory or Redis when you need full atomic/list capabilities.

---

## Capability matrix

| Capability | Memory | Redis | Database |
|------------|--------|-------|----------|
| KV get/set/delete | yes | yes | yes |
| `get_del` / CAS / `set_if_absent` | yes | yes | unsupported |
| `list_*` / `scan` | yes | yes | unsupported |

Custom backends: implement `SaStorage` from `sa-token-adapter` and inject with `Arc` the same way.

## Related

- [Quick start](./quick-start.md)
- [Adapters](./adapter.md)
- [Framework integration](./framework-integration.md)
- [Migrate to 0.2](./migration-0.2.md)
- [Error reference](../reference/error-reference.md)
