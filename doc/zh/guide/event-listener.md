# 事件监听

[English](/guide/event-listener.md) | 中文

实现 `SaTokenListener`，在登录、登出、踢人等生命周期上挂审计、统计或缓存清理。钩子都有默认空实现，按需覆盖即可。

## 何时使用

- 写登录审计日志、刷新在线人数。
- 踢人 / 顶号后通知客户端。
- 权限变更后清本地缓存。

## SaTokenListener 钩子

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
        let _ = event; // 每个事件都会再走一遍
    }
}
```

内置 `LoggingListener` 可直接注册做调试输出。

## DispatchMode

通过自定义 `SaTokenEventBus` 注入分发策略：

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

| 模式 | 行为 |
|------|------|
| `Sequential`（默认） | 按注册顺序 await 每个监听器 |
| `Concurrent` | 并行 await 全部监听器 |
| `Detached` | 后台执行，不阻塞 `publish` 调用方 |

默认 `listener_timeout` 为 5 秒；`EventBusConfig::no_timeout()` 关闭超时。

## 注册方式

**1. Builder（推荐，构建时一并注册）：**

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

`SaTokenState::builder().register_listener(...).build()` 同样可用。

**2. 运行期经 StpUtil：**

```rust
use sa_token_core::StpUtil;

StpUtil::register_listener(Arc::new(AuditListener)); // 未 init → 静默跳过

if let Some(bus) = StpUtil::event_bus() {
    bus.register(Arc::new(AuditListener));
}
```

`event_bus()` 在未初始化时返回 `None`，不会 panic。

## 相关链接

- [StpUtil](./stp-util.md)
- [在线用户](./online-user-management.md)
- [错误参考](/zh/reference/error-reference.md)
