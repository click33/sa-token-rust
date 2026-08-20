# sa-token-rust

中文文档 | [English](README.md)

轻量级 Rust 认证授权框架。设计灵感来自 Dromara sa-token；本仓库为独立实现（MIT OR Apache-2.0），见 [NOTICE](NOTICE)。

面向 Web 与 gRPC：在 Axum、Actix-web、Poem、Rocket、Warp、Salvo、Tide、Gotham、Ntex 与 Tonic 上，使用同一套 `StpUtil` / `SaTokenState` 心智模型完成登录、鉴权与会话管理。

指南：[doc/zh/index.md](doc/zh/index.md)。从 0.1.x 升级：[MIGRATION_0.2.md](MIGRATION_0.2.md)。

## 它能做什么

登录、登出、踢人、顶号由核心 `AuthService` 编排。应用侧通常调用 `StpUtil::login`、`logout`、`kick_out` 等静态门面。例如：`let token = StpUtil::login("10001").await?;`

权限与角色经 `AuthzService`。你可以在代码里用 `has_permission` / `check_role`，也可以在 handler 上挂宏，例如 `#[sa_check_permission("user:add")]`。通配匹配与 Exact 策略见权限指南。

中间件路径鉴权使用 `PathAuthConfig`。公开路由必须写入 `exclude`。`#[sa_ignore]` 只跳过宏插入的检查，**不会**跳过 Layer / 中间件。

存储后端 Memory、Redis、Database 统一经 `SaTokenDao`。插件通过 Cargo feature 切换后端，键布局由 `SaKeys` 管理。

JWT、Nonce、Refresh、OAuth2（含 PKCE）、SSO、WebSocket 鉴权、在线 presence、分布式 Session 与事件总线各自有独立指南，可按需接入。

多账号用 `login_type` 隔离体系，例如管理端与用户端：`StpUtil::builder("42").login_type("admin").device("pc").login(None).await?`。

## 安装

```toml
[dependencies]
sa-token-plugin-axum = "0.2.0"
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

启用 Redis：

```toml
sa-token-plugin-axum = { version = "0.2.0", features = ["redis"] }
```

一行导入：`use sa_token_plugin_axum::*;`

其它插件：`sa-token-plugin-{actix-web,poem,rocket,warp,salvo,tide,gotham,ntex,tonic}`。Actix-web / Rocket / Salvo / Ntex / Gotham 为门面 crate（默认 `v4`、`v05` 等）；`sa-token-plugin-actix-web` 的 `v5` 仅为占位，生产请用 `v4`。

未设置 `storage` 时，`SaTokenState::builder().build()` 会 panic。库代码请使用 `SaTokenConfig::builder().try_build()`，以便拿到 `Result`。

## 最小示例

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

登录：`StpUtil::login("user_10001").await?`。

## 初始化

`SaTokenState::build()` 内部会尝试 `StpUtil::try_init_manager`。应用启动调用一次即可。重复初始化返回 `AlreadyInitialized`，不会静默覆盖全局实例。

库或测试代码更推荐：

```rust
let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(7200)
    .try_build()?;
```

可选前缀：`.token_prefix("Bearer ")`。可选写 Cookie：`.is_write_cookie(true)`，并在响应路径调用 `write_token_cookie`。

## 文档

正式文档在 VitePress 目录 `doc/`：

- [快速入门](doc/zh/guide/quick-start.md)
- [StpUtil](doc/zh/guide/stp-util.md)
- [路径鉴权](doc/zh/guide/path-auth.md)
- [权限匹配与宏](doc/zh/guide/permission-matching.md)
- [存储](doc/zh/guide/storage.md)
- [0.2 迁移](doc/zh/guide/migration-0.2.md)

其余主题见 [doc/zh/index.md](doc/zh/index.md)。仓库根目录 `docs/` 下文件仅为兼容短链 stub，不是现行长文。

## 示例

见 `examples/`：`axum-full-example`、`actix-web-example`、`jwt_example.rs`、`sso_example.rs`、`oauth2_example.rs`、`websocket_online_example.rs` 等。

## 社区

微信交流群：

![sa-token-rust 微信群](https://sa-token.cc/big-file/contact/sa-token-rust--wx-group-qr.png?v=5)

## 贡献与许可证

Issues：https://github.com/sa-tokens/sa-token-rust/issues

MIT OR Apache-2.0。见 `LICENSE-MIT` 与 `LICENSE-APACHE`。
