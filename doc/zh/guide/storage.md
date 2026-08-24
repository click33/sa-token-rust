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

## 可插拔序列化（`SaSerializer`）

写入存储的领域对象（TokenInfo、Session、Nonce、OAuth2/SSO 载荷等）统一经 `SaTokenConfig` 上的可插拔序列化器。调用方优先使用 `SharedSerializer`（Clone 友好枚举）。默认 JSON；可选二进制编码需开启 `fory` feature。

### 默认与选型

| 选择 | 适用场景 |
|------|----------|
| **JSON**（默认） | 兼容 0.1 / 早期 0.2 存量数据；Redis CLI 可读 |
| **fory**（`feature = "fory"`） | 载荷更紧凑；读路径仍可解码存量纯 JSON（滚动升级） |

普通安装**不必**改任何配置：不写 `.serializer(...)` 即保持 JSON。

### 通过 Builder 注入

类型由 `sa-token-core` 再导出（根 crate / 插件在 feature 允许时同样可用）：

```rust
use sa_token_adapter::{JsonSerializer, JsonSerializerConfig};
use sa_token_core::{SaTokenConfig, SharedSerializer};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

// 默认 JSON — 显式写法
let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .serializer(SharedSerializer::Json(JsonSerializer::default()))
    .try_build()?;

// 仅本地调试用的 pretty JSON（生产勿开）
let debug = SharedSerializer::Json(JsonSerializer::with_config(JsonSerializerConfig {
    pretty_print: true,
    ..Default::default()
}));
```

### 可选 fory（二进制）

在依赖的 crate 上打开 feature：

```toml
# 根 meta-crate
sa-token = { version = "0.2.0", features = ["fory"] }

# 或直接依赖 core / adapter
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

二进制字符串载荷带魔数前缀 `\u{0001}STF`（`BINARY_MAGIC`），读路径据此区分格式。

### 滚动升级语义

| 当前序列化器 | 读存量纯 JSON | 读魔数前缀二进制 |
|--------------|---------------|------------------|
| JSON | 可以 | `FormatMismatch` → 表现为 `SaTokenError::SerializationError` |
| fory | 可以（兼容路径） | 可以 |

落地建议：全节点具备 `fory` 能力前继续写 JSON；再切换写路径；旧 JSON 过期或改写完成前保持 fory 读兼容。若已有二进制行再切回 JSON，解码会因格式不匹配失败——先迁移或等 TTL。

### 错误

`SerializerError`（`EncodeFailed` / `DecodeFailed` / `FormatMismatch` / `VersionIncompatible`）经 `Display` 映射为 `SaTokenError::SerializationError(String)`。详见 [错误参考](../reference/error-reference.md)。

### Trait 概览

`SaSerializer` 提供 `name` / `kind` / `encode` / `decode`，以及可选的 `encode_bytes` / `decode_bytes`。应用侧通常只通过 `SaTokenConfigBuilder::serializer` 配置，很少直接调用 trait。

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
- [迁移到 0.2](./migration-0.2.md)
- [错误参考](../reference/error-reference.md)
