# Event listeners

English | [中文](/zh/guide/event-listener.md)

Implement `SaTokenListener` to hook login, logout, kick-out, and related lifecycle events for audit, metrics, or cache invalidation. All hooks have empty defaults — override only what you need.

## When to use

- Write login audit logs or refresh online counts.
- Notify clients after kick-out / replace.
- Clear local caches when grants change.

## SaTokenListener hooks

```rust
use async_trait::async_trait;
use sa_token_core::SaTokenListener;

struct AuditListener;

#[async_trait]
impl SaTokenListener for AuditListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }
    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }
    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }
    async fn on_replaced(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }
    async fn on_renew_timeout(
        &self,
        login_id: &str,
        token: &str,
        login_type: &str,
        timeout_seconds: i64,
    ) {
        let _ = (login_id, token, login_type, timeout_seconds);
    }
    async fn on_banned(&self, login_id: &str, login_type: &str) {
        let _ = (login_id, login_type);
    }
    async fn on_unbanned(&self, login_id: &str, service: &str, login_type: &str) {
        let _ = (login_id, service, login_type);
    }
    async fn on_open_safe(&self, token: &str, service: &str) {
        let _ = (token, service);
    }
    async fn on_close_safe(&self, token: &str, service: &str) {
        let _ = (token, service);
    }
    async fn on_safe_verify(&self, token: &str, service: &str) {
        let _ = (token, service);
    }
    async fn on_grant_changed(&self, login_id: &str, login_type: &str) {
        let _ = (login_id, login_type);
    }
    async fn on_event(&self, event: &sa_token_core::SaTokenEvent) {
        let _ = event; // fired for every event in addition to typed hooks
    }
}
```

Built-in `LoggingListener` is useful for debug logging.

## DispatchMode

Inject a custom `SaTokenEventBus` for dispatch policy:

```rust
use std::time::Duration;
use sa_token_core::{
    event::{DispatchMode, EventBusConfig, SaTokenEventBus},
    SaTokenConfig,
};

let bus = SaTokenEventBus::with_config(EventBusConfig {
    dispatch_mode: DispatchMode::Concurrent, // Sequential | Concurrent | Detached
    listener_timeout: Some(Duration::from_secs(5)),
});

SaTokenConfig::builder()
    .storage(storage)
    .event_bus(bus)
    .register_listener(std::sync::Arc::new(AuditListener))
    .try_build()?;
```

| Mode | Behavior |
|------|----------|
| `Sequential` (default) | Await listeners in registration order |
| `Concurrent` | Await all listeners in parallel |
| `Detached` | Run in the background; does not block `publish` |

Default `listener_timeout` is 5 seconds; use `EventBusConfig::no_timeout()` to disable.

## Registration

**1. Builder (preferred — register at build time):**

```rust
use std::sync::Arc;
use sa_token_core::SaTokenConfig;
use sa_token_storage_memory::MemoryStorage;

SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .register_listener(Arc::new(AuditListener))
    .register_listener(Arc::new(sa_token_core::LoggingListener))
    .try_build()?;
```

`SaTokenState::builder().register_listener(...).build()` works the same way.

**2. Runtime via StpUtil:**

```rust
use sa_token_core::StpUtil;

StpUtil::register_listener(Arc::new(AuditListener)); // no-op before init

if let Some(bus) = StpUtil::event_bus() {
    bus.register(Arc::new(AuditListener));
}
```

`event_bus()` returns `None` before init — it does not panic.

## Related

- [StpUtil](./stp-util.md)
- [Online users](./online-user-management.md)
- [Error reference](/reference/error-reference.md)
