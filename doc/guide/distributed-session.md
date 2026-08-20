# Distributed session

English | [中文](/zh/guide/distributed-session.md)

`DistributedSessionManager` manages **cross-service business sessions** (attributes, service credentials). It is not online presence, and not an alias for account `SaSession`.

## Boundary vs Online

| | Distributed Session | OnlineManager |
|--|---------------------|---------------|
| Purpose | Shared session data across services | Who is online, push, kick notify |
| Typical APIs | `create_session` / `set_attribute` | `mark_online` / `push_to_user` |
| Storage | `DistributedSessionStorage` | `OnlineStore` (local / Dao) |

You can use both; keep the responsibilities separate.

## Storage adapters

In-memory and `SaStorage` / `SaTokenDao` adapters:

```rust
use sa_token_core::{
    DistributedSessionManager, InMemoryDistributedStorage, SaStorageDistributedStorage,
};
use std::sync::Arc;
use std::time::Duration;

// Dev / single process
let storage = Arc::new(InMemoryDistributedStorage::new());

// Same SaStorage / Dao as the app
let storage = Arc::new(SaStorageDistributedStorage::from_dao(manager.dao().clone()));
// or from_config(storage, &config) / new(storage, key_prefix)
```

## Manager

```rust
use sa_token_core::ServiceCredential;
use chrono::Utc;

let dsm = DistributedSessionManager::new(
    storage,
    "order-service".into(),
    Duration::from_secs(3600),
);

dsm.register_service(ServiceCredential {
    service_id: "order-service".into(),
    service_name: "Order".into(),
    secret_key: "svc-secret".into(),
    created_at: Utc::now(),
    permissions: vec![],
})
.await?;
dsm.verify_service("order-service", "svc-secret").await?;

let session = dsm
    .create_session("user_1".into(), token_str.clone())
    .await?;

dsm.set_attribute(&session.session_id, "cart".into(), "[1,2]".into())
    .await?;
let cart = dsm.get_attribute(&session.session_id, "cart").await?;

dsm.refresh_session(&session.session_id).await?;
dsm.delete_session(&session.session_id).await?;
```

By login id: `get_sessions_by_login_id`, `delete_all_sessions`, `delete_sessions_by_token`.

## Attach to SaTokenManager (optional)

```rust
let manager = manager.with_distributed_manager(Arc::new(dsm));
```

You can still hold `DistributedSessionManager` directly in application state.

## Related

- [Online users](/guide/online-user-management.md)
- [Storage](/guide/storage.md)
- [SSO](/guide/sso.md)
