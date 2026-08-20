# 在线用户管理

[English](/guide/online-user-management.md) | 中文

`OnlineManager` 维护 **presence（在线在场）**，不是「库里有没有 token」。有 token ≠ 一定在线；断开 WS / 主动 `mark_offline` 后，token 仍可能有效。

## 本地 vs 分布式

```rust
use sa_token_core::OnlineManager;
use std::sync::Arc;

// 进程内
let online = OnlineManager::local();
// 或 OnlineManager::new()

// 多实例：经 Dao 共享
let online = OnlineManager::distributed(manager.dao().clone());
```

挂到 Manager：

```rust
let manager = manager.with_online_manager(Arc::new(online));
// 或 manager.with_distributed_online() —— 用当前 Dao 建 DistributedOnlineStore
```

## 标记上下线

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

带 `login_type` 的变体：`mark_offline_with_type`、`mark_offline_all_with_type`、`update_activity_with_type`。

`WsAuthManager::authenticate` 成功时若已挂 OnlineManager，会自动 `mark_online`。

## 推送

实现 `MessagePusher`，或用测试向 `InMemoryPusher`：

```rust
use sa_token_core::{InMemoryPusher, MessagePusher, PushMessage};
use async_trait::async_trait;
use std::sync::Arc;

online.register_pusher(Arc::new(InMemoryPusher::new())).await;

online.push_to_user("user_1", "hello".into()).await?;
online.broadcast("maintenance".into()).await?;
online.kick_out_notify("user_1", "kicked".into()).await?;
```

自定义 pusher：实现 `MessagePusher::push`，再 `register_pusher`。

## 边界

| 概念 | 含义 |
|------|------|
| presence | 当前连接/会话在场（OnlineManager） |
| token | 登录凭证是否仍有效（Auth / TokenRepo） |
| 分布式 Session | 跨服务业务 Session 数据（见下一篇），不是 presence |

## 相关链接

- [WebSocket 鉴权](/zh/guide/websocket-auth.md)
- [分布式 Session](/zh/guide/distributed-session.md)
- [事件监听](/zh/guide/event-listener.md)
