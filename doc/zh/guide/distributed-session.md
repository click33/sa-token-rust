# 分布式 Session

[English](/guide/distributed-session.md) | 中文

`DistributedSessionManager` 管的是 **跨服务共享的业务 Session**（属性、服务凭证），不是在线 presence，也不是账号 `SaSession` 的别名。

## 与 Online 的边界

| | Distributed Session | OnlineManager |
|--|---------------------|---------------|
| 目的 | 多服务读写同一会话数据 | 标记谁在线、推送、踢人通知 |
| 典型 API | `create_session` / `set_attribute` | `mark_online` / `push_to_user` |
| 存储 | `DistributedSessionStorage` | `OnlineStore`（local / Dao） |

两者可同时使用，职责不要混。

## 存储适配

内置内存实现与基于 `SaStorage` / `SaTokenDao` 的适配：

```rust
use sa_token_core::{
    DistributedSessionManager, InMemoryDistributedStorage, SaStorageDistributedStorage,
};
use std::sync::Arc;
use std::time::Duration;

// 开发 / 单机
let storage = Arc::new(InMemoryDistributedStorage::new());

// 与业务同一套 SaStorage / Dao
let storage = Arc::new(SaStorageDistributedStorage::from_dao(manager.dao().clone()));
// 或 from_config(storage, &config) / new(storage, key_prefix)
```

## 管理器

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

按登录账号批量：`get_sessions_by_login_id`、`delete_all_sessions`、`delete_sessions_by_token`。

## 挂到 SaTokenManager（可选）

```rust
let manager = manager.with_distributed_manager(Arc::new(dsm));
```

也可在应用状态中直接持有 `DistributedSessionManager`。

## 相关链接

- [在线用户](/zh/guide/online-user-management.md)
- [存储](/zh/guide/storage.md)
- [SSO](/zh/guide/sso.md)
