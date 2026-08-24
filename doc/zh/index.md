# sa-token-rust

[English](/)

轻量级 Rust 认证授权框架。设计灵感来自 [Dromara sa-token](https://github.com/dromara/sa-token)；本仓库为独立实现（MIT OR Apache-2.0），见仓库根目录 `NOTICE`。

面向 Web 与 gRPC：在 Axum、Actix-web、Poem、Rocket、Warp、Salvo、Tide、Gotham、Ntex 与 Tonic 上，使用同一套 `StpUtil` / `SaTokenState` 心智模型完成登录、鉴权与会话管理。

**从这里开始：** [快速入门](/zh/guide/quick-start.md)。从 0.1.x 升级请先读 [迁移到 0.2](/zh/guide/migration-0.2.md)。

## 它能做什么

登录、登出、踢人、顶号由核心 `AuthService` 编排。应用侧通常调用 `StpUtil::login`、`logout`、`kick_out` 等静态门面。例如：`let token = StpUtil::login("10001").await?;`

权限与角色经 `AuthzService`。你可以在代码里用 `has_permission` / `check_role`，也可以在 handler 上挂宏，例如 `#[sa_check_permission("user:add")]`。通配匹配与 Exact 策略见 [权限匹配与宏](/zh/guide/permission-matching.md)。

中间件路径鉴权使用 `PathAuthConfig`。公开路由必须写入 `exclude`。`#[sa_ignore]` 只跳过宏插入的检查，**不会**跳过 Layer / 中间件。详见 [路径鉴权](/zh/guide/path-auth.md)。

存储后端 Memory、Redis、Database 统一经 `SaTokenDao`。插件通过 Cargo feature 切换后端，键布局由 `SaKeys` 管理。存储载荷默认经可插拔 `SaSerializer` / `SharedSerializer` 编为 JSON（可选 `fory` 二进制 — 见 [存储](/zh/guide/storage.md)）。Token 读写走核心 `token_io`（`read_token` / `write_token_cookie`），与各框架适配器一致。

JWT、Nonce、Refresh、OAuth2（含 PKCE）、SSO、WebSocket 鉴权、在线 presence、分布式 Session 与事件总线各自有独立指南，可按需接入。

多账号用 `login_type` 隔离体系，例如管理端与用户端。可使用 `StpUtil::builder(...).login_type("admin")`，或 `StpUtil::stp_logic("admin")?` / `manager.stp_logic("admin")` 绑定门面（`SaLogic` 为廉价 Clone，无全局注册表）。

## 项目结构

```text
sa-token-rust/
├── sa-token-core/           # Dao、keys、service、token_io、oauth2/、sso/、StpUtil、SaLogic
├── sa-token-adapter/        # SaStorage、SaSerializer、SaRequest / SaResponse、scan
├── sa-token-macro/          # 过程宏
├── sa-token-plugin-common/  # SaTokenState、rejection（各插件再导出）
├── sa-token-storage-*/      # memory / redis / database
├── sa-token-plugin-*/       # axum、actix-web、poem、rocket、warp、salvo、tide、gotham、ntex、tonic
└── doc/                     # 本站点（VitePress）
```

门面 crate（Actix-web、Rocket、Salvo、Gotham、Ntex）通过 Cargo features 选择框架大版本。共享类型在 `sa-token-plugin-common`，不再有 `*-core` crate。

## 社区

微信交流群：

![sa-token-rust 微信群](https://res.dev33.cn/contact/sa-token-rust--wx-group-qr.png)

Issues：https://github.com/sa-tokens/sa-token-rust/issues

## 许可证

MIT OR Apache-2.0。见 `LICENSE-MIT` 与 `LICENSE-APACHE`。
