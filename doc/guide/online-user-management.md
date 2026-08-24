# Online user management

English | [中文](/zh/guide/online-user-management.md)

`OnlineManager` tracks **presence**, not “whether a token exists in storage”. Having a token does not imply online; after a WS disconnect or `mark_offline`, the token may still be valid.

## Local vs distributed

```rust
use sa_token_core::OnlineManager;
use std::sync::Arc;

// In-process
let online = OnlineManager::local();
// or OnlineManager::new()

// Multi-instance: share via Dao
let online = OnlineManager::distributed(manager.dao().clone());
```

Attach to the Manager:

```rust
let manager = manager.with_online_manager(Arc::new(online));
// or manager.with_distributed_online() — builds DistributedOnlineStore from current Dao
```

## Mark online / offline

```rust
use sa_token_core::OnlineUser;
use chrono::Utc;
use std::collections::HashMap;

let user = OnlineUser {
    login_type: "default".into(),
    login_id: "user_1".into(),
    token: token_str.clone(),
    device: "pc".into(),
    connect_time: Utc::now(),
    last_activity: Utc::now(),
    metadata: HashMap::new(),
};
online.mark_online(user).await?;

online.is_online("user_1").await?;
online.get_user_sessions("user_1").await?;
online.update_activity("user_1", &token_str).await?;

online.mark_offline("user_1", &token_str).await?;
online.mark_offline_all("user_1").await?;
```

Typed variants: `mark_offline_with_type`, `mark_offline_all_with_type`, `update_activity_with_type`.

`WsAuthManager::authenticate` calls `mark_online` automatically when an OnlineManager is attached.

## Pushing

Implement `MessagePusher`, or use `InMemoryPusher` in tests:

```rust
use sa_token_core::{InMemoryPusher, MessagePusher, PushMessage};
use async_trait::async_trait;
use std::sync::Arc;

online.register_pusher(Arc::new(InMemoryPusher::new())).await;

online.push_to_user("user_1", "hello".into()).await?;
online.broadcast("maintenance".into()).await?;
online.kick_out_notify("user_1", "kicked".into()).await?;
```

Custom pushers implement `MessagePusher::push`, then `register_pusher`.

## Boundaries

| Concept | Meaning |
|---------|---------|
| Presence | Connection / session is present (`OnlineManager`) |
| Token | Login credential still valid (Auth / TokenRepo) |
| Distributed session | Cross-service business session data (next guide), not presence |

## Related

- [WebSocket auth](/guide/websocket-auth.md)
- [Distributed session](/guide/distributed-session.md)
- [Event listeners](/guide/event-listener.md)
