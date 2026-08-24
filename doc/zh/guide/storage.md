# 存储后端

[English](/guide/storage.md) | 中文

Token、Session、权限缓存等都落在 `SaStorage` 上。0.2 官方提供 Memory / Redis / Database（PostgreSQL）三种实现；业务层应通过 `SaTokenDao` 访问，而不是在服务里直接握底层存储。

## 插件 Feature

在框架插件（如 `sa-token-plugin-axum`）上启用对应 feature 后，可直接 `use` 重导出的存储类型：

| Feature | Crate | 说明 |
|---------|-------|------|
| `memory`（默认） | `sa-token-storage-memory` | 进程内存储 |
| `redis` | `sa-token-storage-redis` | Redis |
| `database` | `sa-token-storage-database` | 关系库 KV（默认 `postgres`） |
| `full` | 上述全部 | 一并启用 |

```toml
sa-token-plugin-axum = { version = "0.2.0", features = ["redis"] }
# 或单独依赖
# sa-token-storage-redis = "0.2.0"
```

## 注入 Builder

所有后端都要包成 `Arc<dyn SaStorage>`（或具体类型的 `Arc`，会自动协变）再交给 Builder：

```rust
use std::sync::Arc;
use sa_token_plugin_axum::*; // 或 MemoryStorage / RedisStorage / DatabaseStorage

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(86400)
    .build();
```

库代码更推荐 `SaTokenConfig::builder().storage(...).try_build()?`，再 `StpUtil::try_init_manager`。

## SaTokenDao

`SaTokenManager` 内部用 `SaTokenDao` 作为存储唯一收口：键名（`SaKeys`）、序列化、TTL 都在这一层完成。Repository / Service **不应**直接持有 `SaStorage`。应用侧几乎只需选后端并注入；自定义键或原子原语时再查阅 `SaTokenDao` API。

---

## MemoryStorage

适合开发、测试与单机无持久化场景。

```rust
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
// 可选：主动清理过期条目
storage.cleanup_expired().await;
```

特点：无外部依赖、读写快；进程重启后数据丢失，不能跨进程共享。

---

## RedisStorage

适合生产、多实例共享会话。常用构造：

```rust
use sa_token_storage_redis::{RedisStorage, RedisConfig};
use std::sync::Arc;

// 1) URL + 键前缀
let storage = RedisStorage::new(
    "redis://:password@localhost:6379/0",
    "sa-token:",
).await?;

// 2) 便捷：物理前缀为空（逻辑键由 SaKeys 提供）
let storage = RedisStorage::connect("redis://localhost:6379/0").await?;

// 3) 配置结构体
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

也可用 `RedisStorage::builder().host(...).port(...).key_prefix(...).build().await?`。

URL 示例：`redis://localhost:6379/0`、`redis://:mypass@localhost:6379/0`。

---

## DatabaseStorage

基于 sqlx 的 PostgreSQL KV 存储。crate 默认 feature 为 `postgres`：

```toml
sa-token-storage-database = "0.2.0"
# 等价于 features = ["postgres"]
```

```rust
use sa_token_storage_database::DatabaseStorage;
use std::sync::Arc;

let storage = DatabaseStorage::new("postgres://user:pass@localhost/db").await?;
// 或 DatabaseStorage::from_pool(pool)

let state = SaTokenState::builder()
    .storage(Arc::new(storage))
    .build();
```

`new` 会建连并执行内嵌 DDL（幂等）。当前实现支持基本 KV（`get` / `set` / `delete` 等）；`get_del`、CAS、`list_*`、`scan` 等会返回 `StorageError::Unsupported`。需要完整原子/列表能力时用 Memory 或 Redis。

---

## 能力对照

| 能力 | Memory | Redis | Database |
|------|--------|-------|----------|
| KV get/set/delete | 是 | 是 | 是 |
| `get_del` / CAS / `set_if_absent` | 是 | 是 | 不支持 |
| `list_*` / `scan` | 是 | 是 | 不支持 |

自定义后端：在 `sa-token-adapter` 中实现 `SaStorage`，同样以 `Arc` 注入 Builder。

## 相关文档

- [快速入门](./quick-start.md)
- [框架适配器](./adapter.md)
- [框架集成](./framework-integration.md)
