# StpUtil

English | [中文](/zh/guide/stp-util.md)

`StpUtil` is the static façade over the process-wide `SaTokenManager`. Web plugins (`SaTokenState` / `SaTokenConfig::try_build`) call `try_init_manager` at startup. Prefer `try_*` APIs so missing init returns `Result` instead of panicking.

## When to use

- Login / authz from handlers, macro-expanded checks, or background tasks.
- Parameterless access to the current request context (after middleware injects `SaTokenContext`).

## Initialization

```rust
use sa_token_core::{SaTokenConfig, SaTokenError, StpUtil};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(7200)
    .try_build()?; // calls try_init_manager; if already set, logs a warn and returns this Manager

match StpUtil::try_init_manager(manager.clone()) {
    Ok(()) => {}
    Err(SaTokenError::AlreadyInitialized) => {}
    Err(e) => return Err(e),
}

let mgr = StpUtil::try_get_manager()?; // NotInitialized if never initialized
```

| API | Behavior |
|-----|----------|
| `try_init_manager` | Ok / `AlreadyInitialized` (no panic) |
| `try_get_manager` | Ok / `NotInitialized` |
| `init_manager` | Deprecated; panics on failure |
| `is_login` | Returns **`false` if not initialized** |
| `event_bus()` | `Option<&SaTokenEventBus>`; `None` before init |
| `register_listener` | No-op before init |

Plugin path: `SaTokenState::builder().storage(...).build()` also initializes the global manager.

## LoginId

Login ids implement `LoginId`: `&str` / `String`, plus integers such as `i32` / `i64` / `u32` / `u64`. Internally they become string keys.

```rust
let t1 = StpUtil::login("user_10001").await?;
let t2 = StpUtil::login(10001).await?;
```

## Login family

```rust
let token = StpUtil::login("10001").await?;

let token = StpUtil::login_with_type("10001", "admin").await?;

use serde_json::json;
let token = StpUtil::login_with_extra("10001", json!({"ip": "10.0.0.1"})).await?;
```

## TokenBuilder

Fluent login; finish with `.login(None)` (`None` keeps the builder id; `Some(id)` overrides).

```rust
use serde_json::json;

let token = StpUtil::builder("10001")
    .login_type("admin")
    .device("pc")
    .extra_data(json!({"channel": "web"}))
    .nonce("once-abc")          // requires enable_nonce
    // .expire_time(some_utc)   // absolute expiry
    .login(None)
    .await?;
```

See [Multi-account](./multi-account.md) for `login_type` isolation.

## Logout and kick

```rust
StpUtil::logout(&token).await?;
StpUtil::logout_current().await?;
StpUtil::logout_by_login_id("10001").await?;

StpUtil::kick_out("10001").await?;
StpUtil::kick_out_with_type("admin", "10001").await?;
```

`logout` ends the session normally; `kick_out` marks KickOut so callers can tell forced offline apart.

## Current request context

After middleware / Layer runs `run_auth_flow`:

```rust
let token = StpUtil::get_token_value()?;
let login_id = StpUtil::get_login_id_as_string().await?;
let id_i64 = StpUtil::get_login_id_as_long().await?; // non-numeric → LoginIdNotNumber

if StpUtil::is_login_current() { /* weak: context has a token string */ }

StpUtil::check_login_current_async().await?; // strong: token still valid in storage
```

## Login status

```rust
// false when not initialized or token invalid
let ok = StpUtil::is_login(&token).await;
let ok = StpUtil::is_login_by_login_id("10001").await;
```

## Permissions and roles

`has_*` returns `bool` (`false` if not initialized); `check_*` returns `Err` on denial.

```rust
StpUtil::set_permissions("10001", vec!["user:add".into(), "user:*".into()]).await?;
StpUtil::set_roles("10001", vec!["admin".into()]).await?;

if StpUtil::has_permission("10001", "user:delete").await { /* ... */ }
StpUtil::check_permission("10001", "user:add").await?;

StpUtil::has_all_permissions("10001", &["user:add", "user:list"]).await;
StpUtil::has_any_permission("10001", &["user:add", "user:delete"]).await;
StpUtil::check_role("10001", "admin").await?;
```

Wildcards and macros: [Permissions and macros](./permission-matching.md).

## Event bus

```rust
use std::sync::Arc;
use sa_token_core::SaTokenListener;

SaTokenConfig::builder()
    .storage(storage)
    .register_listener(Arc::new(MyListener))
    .try_build()?;

if let Some(bus) = StpUtil::event_bus() {
    bus.register(Arc::new(MyListener));
}
StpUtil::register_listener(Arc::new(MyListener)); // no-op before init
```

Hooks and `DispatchMode`: [Event listeners](./event-listener.md).

## Related

- [Quick start](./quick-start.md)
- [Path auth](./path-auth.md)
- [Permissions and macros](./permission-matching.md)
- [Error reference](/reference/error-reference.md)
