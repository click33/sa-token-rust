# 快速入门

[English](/guide/quick-start.md)

几分钟内把 sa-token-rust 接到一个 Axum 服务上。本页覆盖依赖、初始化、路径鉴权、登录与后续阅读。

## 添加依赖

推荐只依赖对应框架的插件 crate（会再导出核心类型与宏）：

```toml
[dependencies]
sa-token-plugin-axum = "0.2.0"
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

一行导入：

```rust
use sa_token_plugin_axum::*;
```

### 存储 feature

| Feature | 说明 |
|---------|------|
| `memory` | 默认，进程内存储 |
| `redis` | Redis 后端 |
| `database` | 数据库后端（基本 KV；高级能力见 [存储](/zh/guide/storage.md)） |
| `full` | 上述全部 |

```toml
sa-token-plugin-axum = { version = "0.2.0", features = ["redis"] }
```

### 选择插件

| Crate | 说明 |
|-------|------|
| `sa-token-plugin-axum` | 一体化，默认 `axum-08` + `memory` |
| `sa-token-plugin-poem` / `warp` / `tide` | 一体化 |
| `sa-token-plugin-actix-web` | 门面，默认 `v4`；`v5` 仅为占位，生产请用 `v4` |
| `sa-token-plugin-rocket` / `salvo` / `gotham` / `ntex` | 门面，用 feature 选大版本 |
| `sa-token-plugin-tonic` | gRPC |

`SaTokenState` 定义在 `sa-token-plugin-common`，各插件再导出。不要依赖已删除的 `*-core` crate。

需要细粒度依赖时，也可以显式引入 `sa-token-core`、`sa-token-storage-memory` 等；日常应用用插件一行导入即可。

## 最小可运行示例

```rust
use std::sync::Arc;
use axum::{routing::get, Router};
use sa_token_plugin_axum::*;
use sa_token_core::router::PathAuthConfig;

#[sa_check_login]
async fn me() -> SaTokenResult<&'static str> {
    Ok("ok")
}

async fn health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .timeout(86400)
        .build();

    let path_auth = PathAuthConfig::new()
        .include(vec!["/**".into()])
        .exclude(vec!["/health".into()]);

    let app = Router::new()
        .route("/health", get(health))
        .route("/me", get(me))
        .layer(SaTokenLayer::with_path_auth(state, path_auth));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

要点：

- `SaTokenState::builder().build()` 会尝试 `StpUtil::try_init_manager`。未设置 `storage` 时会 panic。
- 公开路径必须写进 `PathAuthConfig::exclude`。`#[sa_ignore]` **不会**放行中间件。
- 受保护路由可继续用 `#[sa_check_login]` / `#[sa_check_permission(...)]` 做声明式校验。

## 登录与登出

在任意已初始化的上下文中：

```rust
let token = StpUtil::login("user_10001").await?;
StpUtil::logout(&token).await?;
```

客户端默认通过 Header（或 Cookie / query，取决于 `is_read_*`）携带 token。名称由 `token_name` 决定（默认 `"sa-token"`）。可选前缀：

```rust
SaTokenConfig::builder()
    .storage(storage)
    .token_prefix("Bearer ")
    .try_build()?;
```

需要登录后写 Cookie 时，打开 `.is_write_cookie(true)`，并在响应路径调用 `write_token_cookie`（见 `token_io`）。默认不写 Cookie。

## 库代码：用 `try_build`

应用启动用 `SaTokenState` 很方便；库、测试或需要显式 `Result` 时，优先：

```rust
use std::sync::Arc;
use sa_token_core::SaTokenConfig;
use sa_token_storage_memory::MemoryStorage;

let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(7200)
    .auto_renew(false) // 0.2 默认即为 false
    .try_build()?;

StpUtil::try_init_manager(manager)?;
```

`try_build` 会在缺少 storage、JWT 密钥不合法等情况返回 `Err(SaTokenError::ConfigError)`，而不是在库路径 panic。重复 `try_init_manager` 返回 `AlreadyInitialized`，不会静默覆盖全局 Manager。

## 下一步

- [StpUtil](/zh/guide/stp-util.md) — 登录态、权限、会话 API
- [路径鉴权](/zh/guide/path-auth.md) — `include` / `exclude` / 校验器
- [框架集成](/zh/guide/framework-integration.md) — 各 Web / gRPC 插件对照
- [迁移到 0.2](/zh/guide/migration-0.2.md) — 从 0.1.x 升级
- 仓库 `examples/` — `axum-full-example`、`actix-web-example` 等
