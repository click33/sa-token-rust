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
| `register_listener` | Synchronous; no-op before init (do **not** `.await`) |

Plugin path: `SaTokenState::builder().storage(...).build()` also initializes the global manager.

## LoginId

Login ids implement `LoginId`: `&str` / `String`, plus integers such as `i32` / `i64` / `u32` / `u64`. Internally they become string keys.

```rust
let t1 = StpUtil::login("user_10001").await?;
let t2 = StpUtil::login(10001).await?;
```

## Login family and `login_type`

```rust
// Always uses the default login_type ("default") — does NOT follow request context
let token = StpUtil::login("10001").await?;
let token = StpUtil::login_with_extra("10001", json!({"ip": "10.0.0.1"})).await?;

// Explicit non-default account system
let token = StpUtil::login_with_type("10001", "admin").await?;
```

**Important:** `login` / `login_with_extra` always log into the **default** account system. They do **not** call `resolve_login_type`. For `admin` / `user` / other types, use `login_with_type`, `TokenBuilder`, or a bound [`SaLogic`](./multi-account.md).

Most **other** short APIs (`kick_out`, `get_session`, `disable`, `has_permission`, …) use the current request `login_type` when present, otherwise `default`. Explicit `*_with_type` variants never guess.

## TokenBuilder

Fluent login; finish with `.login(None)` (`None` keeps the builder id; `Some(id)` overrides).

```rust
use chrono::{Duration, Utc};
use serde_json::json;

let token = StpUtil::builder("10001")
    .login_type("admin")
    .device("pc")
    .extra_data(json!({"channel": "web"}))
    .nonce("once-abc")                    // requires enable_nonce
    .expire_at(Utc::now() + Duration::hours(2))  // absolute expiry
    // .expire_at_unix(1_700_000_000)     // or Unix seconds
    .login(None)
    .await?;
```

`expire_time(...)` still compiles as a **deprecated** alias of `expire_at`; prefer `expire_at` / `expire_at_unix` in new code.

See [Multi-account](./multi-account.md) for `login_type` isolation.

## Logout and kick

```rust
StpUtil::logout(&token).await?;
StpUtil::logout_current().await?;
StpUtil::logout_by_login_id("10001").await?; // current login_type, else default

StpUtil::kick_out("10001").await?;
StpUtil::kick_out_with_type("admin", "10001").await?;
StpUtil::kick_out_by_token(&token).await?;   // kick one session by token value
```

`logout` ends the session normally; `kick_out` / `kick_out_by_token` mark KickOut so callers can tell forced offline apart.

## Token-Session

Per-token session (separate from the account session keyed by `login_id`):

```rust
let mut sess = StpUtil::get_token_session(&token).await?;
// or after middleware: StpUtil::get_token_session_current().await?;

sess.set("cart_id", "c-9")?;
StpUtil::save_token_session(&token, &sess).await?;
StpUtil::delete_token_session(&token).await?;
```

Related config: `right_now_create_token_session`, `token_session_check_login`, `is_logout_keep_token_session`.

## Disable (typed)

```rust
// Uses current request login_type, else default
StpUtil::disable("10001", 86400).await?;
StpUtil::disable_level("10001", "comment", 2, 3600).await?;

// Explicit account system
StpUtil::disable_with_type("admin", "10001", 86400).await?;

let level = StpUtil::get_disable_level("10001", "comment").await?;
StpUtil::check_disable("10001").await?;
StpUtil::untie_disable("10001", "comment").await?;
```

More disable / safe / same-token APIs: [Security features](./security-features.md).

## Current request context

After middleware / Layer runs `run_auth_flow`:

```rust
let token = StpUtil::get_token_value()?;
let login_id = StpUtil::get_login_id_as_string().await?;
let id_i64 = StpUtil::get_login_id_as_long().await?; // non-numeric → LoginIdNotNumber

if StpUtil::is_login_current() { /* weak: context has a token string */ }

StpUtil::check_login_current_async().await?; // strong: token still valid in storage
```

`#[sa_check_login]` expands to the async storage check (`check_login_current_async`); handlers that use the macro must be `async`.

## Login status

```rust
// false when not initialized or token invalid
let ok = StpUtil::is_login(&token).await;
let ok = StpUtil::is_login_by_login_id("10001").await;
```

## Permissions and roles

`has_*` returns `bool` (`false` if not initialized); `check_*` returns `Err` on denial. Do **not** use `?` on `has_*`.

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
StpUtil::register_listener(Arc::new(MyListener)); // no-op before init; not async
```

Hooks and `DispatchMode`: [Event listeners](./event-listener.md).

## Related

- [Quick start](./quick-start.md)
- [Multi-account](./multi-account.md)
- [Path auth](./path-auth.md)
- [Permissions and macros](./permission-matching.md)
- [Security features](./security-features.md)
- [Error reference](/reference/error-reference.md)
