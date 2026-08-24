# 迁移到 0.2.0

[English](/guide/migration-0.2.md)

从 0.1.x 升到 0.2.0 时，请按本页核对行为变更与 API 替换。完整双语文档亦在仓库根目录 [MIGRATION_0.2.md](https://github.com/sa-tokens/sa-token-rust/blob/main/MIGRATION_0.2.md)。

设计灵感来自 Dromara sa-token；本仓库为独立实现（MIT OR Apache-2.0），见 `NOTICE`。

## 可能静默影响生产的行为

### `auto_renew` 默认 `false`

0.1.x 读 token 可能写回 TTL。0.2.0 默认关闭，避免每次读取都写存储。需要旧行为时显式开启：

```rust
SaTokenConfig::builder()
    .storage(storage)
    .auto_renew(true)
    .renew_threshold(300)
    .try_build()?;
```

### `is_read_*` 真正生效

`is_read_header` / `is_read_cookie` / `is_read_body` 经 `token_io::read_token` 控制适配器如何取 token。生产若只走 Header，不要关掉 `is_read_header`。

### JWT

- 使用 `TokenStyle::Jwt` 但缺少 / 空 `jwt_secret_key` 时，`try_build` / `TokenGenerator` 返回 `Err(SaTokenError::ConfigError)`，库路径不再 panic。
- `jwt_fallback_on_error` 默认 `false`。JWT 失败不再悄悄变成 UUID。

### `#[sa_ignore]` 不跳过中间件

公开路径必须写入 `PathAuthConfig::exclude`。该属性只跳过宏插入的校验，不会绕过 Layer / Middleware。

### 在线用户是 presence

`OnlineManager::new()` 仍是进程内。跨实例用 `with_distributed_online()`。HTTP 登录不会自动 `mark_online`。

### `token_prefix`（存在）

可选配置：`.token_prefix("Bearer ")`。

- 读 token 时由 `token_io::apply_token_prefix` 应用。
- `None`（默认）仍剥离开头的 `Bearer `。
- 空字符串在 `try_build` 时拒绝。

Token 键名仍是 `token_name`（默认 `"sa-token"`），与前缀是两回事。

### Cookie：`is_write_cookie`（存在）

登录不会自动 `Set-Cookie`。需要写 Cookie 时：

```rust
SaTokenConfig::builder()
    .storage(storage)
    .is_write_cookie(true)
    .cookie_http_only(true)
    .try_build()?;
```

在响应路径调用 `write_token_cookie`；登出用 `delete_token_cookie`。开关为 `false`（默认）时二者为空操作。

### 可插拔存储编码（`SaSerializer`）

TokenInfo、Session、Nonce、OAuth2/SSO 等存储载荷经 `SaTokenConfig.serializer`（`SharedSerializer`）。默认 JSON。可选二进制需 Cargo feature `fory`，并 `.serializer(SharedSerializer::from(ForySerializer::default()))`。Fory 仍可**读取**存量纯 JSON（滚动升级）；若已有二进制行再切回 JSON，会因格式不匹配失败。完整说明：[存储](./storage.md)。

## 已移除与替代

| 已移除 / 废弃 | 替代 |
|---------------|------|
| `SaStorage::keys` | `SaStorage::scan` 直到 `next_cursor == 0` |
| 服务直接握 `SaStorage` | `SaTokenDao`（`set_object` / `get_object` / `cas` / `list_*`） |
| `sa-token-plugin-*-core` | `sa-token-plugin-common`（`SaTokenState`） |
| `FrameworkAdapter` | `sa_token_adapter::plugin::SaTokenPlugin` |
| `init_manager` 主路径 | `try_init_manager` → `Result` |
| `put_stp_logic` / 全局注册 | **废弃空操作** — 改用 `SaLogic::new` / `StpUtil::stp_logic`（廉价 Clone 门面，无注册表） |
| 进程内 OAuth2/SSO `HashMap` | Dao 后端存储 |

```rust
// 0.1.x
// use sa_token_plugin_axum_core::SaTokenState;

// 0.2.0
use sa_token_plugin_common::SaTokenState;
// 或：use sa_token_plugin_axum::*;
```

## 签名与模块

优先使用 `try_build` / `try_init_manager` / `try_get_manager`。适配器读 token 走 `token_io::read_token`。登录与授权经 `AuthService` / `AuthzService`。多账号用 `login_type` + `SaLogic`。`StpUtil::login` 固定 default；其他体系用 `login_with_type` / `TokenBuilder` / `SaLogic`。

新增真实路径包括：`dao.rs`、`keys.rs`、`token_io.rs`、`codec.rs`、`service/`、`stp_logic.rs`、`oauth2/`、`sso/`、`cleanup/`、`sa-token-plugin-common`。Adapter 增加 `SaSerializer` / `SharedSerializer`。Dao **没有** `set_json`；配置错误类型是 `ConfigError`。

## 存储能力（简表）

| 能力 | Memory | Redis | Database |
|------|--------|-------|----------|
| 基本 KV | 是 | 是 | 是 |
| `get_del` / CAS / list / `scan` | 是 | 是 | **不支持** |

nonce 一次性消费、在线索引、多端列表暂勿依赖 database 后端。

## 升级清单

1. 所有 `sa-token-*` 升到 `0.2.0`。
2. `*-core` import 改为 `sa-token-plugin-common` / 插件 prelude。
3. `init_manager` → `try_init_manager`；库代码用 `try_build`。
4. 处理 Token 生成、在线用户、JWT 的 `Result`。
5. 仅在需要旧续期时 `auto_renew(true)`。
6. 公开路由改用 `PathAuthConfig::exclude`。
7. 按需配置 `token_prefix` / `is_write_cookie`。
8. 重读 OAuth2（密钥哈希、PKCE）与 SSO 票据消费。
9. `put_stp_logic` → `SaLogic::new` / `StpUtil::stp_logic`（注册表已取消；旧 API 为空操作）。
10. 若需非 JSON 存储编码，启用 `fory` 并设置 `.serializer(...)` — 见 [存储](/zh/guide/storage.md)。
11. `cargo check --workspace`，再 `cargo clippy --workspace --lib`。

## 相关链接

- [快速入门](/zh/guide/quick-start.md)
- [路径鉴权](/zh/guide/path-auth.md)
- [存储](/zh/guide/storage.md)
- [错误参考](/zh/reference/error-reference.md)
- Issues：https://github.com/sa-tokens/sa-token-rust/issues
