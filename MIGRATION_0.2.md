# Migration Guide: sa-token-rust 0.1.x → 0.2.0

[简体中文](#简体中文) | [English](#english)

This document is the single source of breaking changes for 0.2.0.
Design is inspired by the Dromara sa-token project; this tree is an independent Rust implementation (MIT OR Apache-2.0). See `NOTICE`.

VitePress mirrors: [English guide](doc/guide/migration-0.2.md) · [中文指南](doc/zh/guide/migration-0.2.md).

---

<a id="english"></a>
# English

## 1. Behaviour that can silently change production

### 1.1 `auto_renew` defaults to `false`

Previously a token read could rewrite TTL. Since 0.2.0 the default is off to avoid a storage write on every read.

```rust
SaTokenConfig::builder()
    .storage(storage)
    .auto_renew(true)
    .renew_threshold(300)
    .try_build()?;
```

### 1.2 `is_read_header` / `is_read_cookie` / `is_read_body`

These flags now actually control token extraction in framework adapters via `token_io::read_token`. Do not disable `is_read_header` if clients send the token in a header.

### 1.3 JWT construction

- Missing / empty `jwt_secret_key` with `TokenStyle::Jwt` → `Err(SaTokenError::ConfigError)` from `try_build` / `TokenGenerator` (no library-path panic).
- `jwt_fallback_on_error` default is **`false`**. A failed JWT no longer silently becomes a UUID. Opt in with `.jwt_fallback_on_error(true)` only if you understand the risk.

### 1.4 `#[sa_ignore]` does **not** skip middleware

Path allow-lists belong in `PathAuthConfig::exclude`. The attribute only skips the **macro-inserted** check.

### 1.5 Online users are presence, not “has a token”

`OnlineManager::new()` stays process-local. Cross-instance presence requires `SaTokenManager::with_distributed_online()`. HTTP login does not call `mark_online`.

### 1.6 `token_prefix` (exists)

Optional field on `SaTokenConfig` / builder: `.token_prefix("Bearer ")`.

- Applied by `token_io::apply_token_prefix` when reading tokens.
- `None` (default) still strips a leading `Bearer ` for compatibility.
- Empty string is rejected at `try_build` time.

Token **name** (header / cookie / query key) remains `token_name` (default `"sa-token"`). Do not confuse the two.

### 1.7 Cookie writes: `is_write_cookie` (exists)

Login does **not** automatically `Set-Cookie`. Cookie writes are opt-in:

```rust
SaTokenConfig::builder()
    .storage(storage)
    .is_write_cookie(true)
    .cookie_http_only(true)
    .try_build()?;
```

Handlers / adapters that want to emit the cookie must call `write_token_cookie` (and `delete_token_cookie` on logout). When `is_write_cookie` is `false` (default), those helpers are no-ops. Related cookie options live under `TokenCookieConfig` (`domain`, `path`, `secure`, `same_site`, …).

---

## 2. Removed items

| Removed | Replacement |
|---------|-------------|
| `SaStorage::keys(pattern)` | `SaStorage::scan(pattern, cursor, limit)` until `next_cursor == 0` |
| Direct `SaStorage` in services | `SaTokenDao` (`set_object` / `get_object` / `take_string` / `cas` / `list_*`) |
| `sa-token-plugin-*-core` crates | `sa-token-plugin-common` (`SaTokenState`, rejection helpers) |
| `PermissionChecker` / `RoleChecker` (if still imported) | `StpInterface` + `PermissionMatcher` via `AuthzService` |
| `FrameworkAdapter` | `sa_token_adapter::plugin::SaTokenPlugin` |
| `StpUtil::init_manager` as the happy path | `StpUtil::try_init_manager` → `Result` (`AlreadyInitialized` is recoverable) |
| `TokenGenerator::generate_*` returning `TokenValue` | `SaTokenResult<TokenValue>` |
| `OnlineManager` methods returning `bool`/`usize` without I/O errors | `SaTokenResult<_>` |
| Process-local OAuth2/SSO `HashMap` stores | Dao-backed stores |
| `put_stp_logic` / global SaLogic registry | **Deprecated no-ops** — use `SaLogic::new(login_type, manager)` or `StpUtil::stp_logic` (cloneable façade; no process-wide map) |

### 2.1 Import map (`*-core` → common)

```rust
// 0.1.x
// use sa_token_plugin_axum_core::SaTokenState;

// 0.2.0 — re-exported from each plugin, or:
use sa_token_plugin_common::SaTokenState;
use sa_token_plugin_axum::*; // also `pub use sa_token_plugin_common as common`
```

Actix / Rocket / Salvo / Gotham / Ntex façades likewise re-export `SaTokenState` from `sa-token-plugin-common`. Do not depend on `sa-token-plugin-*-core`.

---

## 3. Signature / API changes

| API | 0.2.0 |
|-----|--------|
| `StpUtil::try_init_manager` / `try_get_manager` | `SaTokenResult` (`AlreadyInitialized` / `NotInitialized`) |
| `SaTokenConfigBuilder::try_build` / `try_build_config` | JWT + storage checks return `Err` |
| `SaTokenConfigBuilder::serializer` | Inject `SharedSerializer` (default JSON; optional `fory`) |
| `SaTokenConfigBuilder::build` | Still panics on missing storage; prefer `try_build` in libraries |
| `TokenGenerator::generate_with_login_id` | `SaTokenResult<TokenValue>` |
| `router::extract_token(req, token_name)` | **Unchanged** (`&str` name, not `&SaTokenConfig`) |
| Token read in adapters | Prefer `token_io::read_token(req, &config)` |
| `SaTokenEventBus` | `DispatchMode::{Sequential, Concurrent, Detached}` + listener timeout |
| `AuthService` / `AuthzService` | Login/logout/grants go through services, not Manager internals |
| `SaTokenContext` | Request-scoped; no `request` field — macros use `RequestAuthMeta` |
| Multi-account | `login_type` + `SaLogic` (no process-wide logic map) |
| `OAuth2` client secret | Argon2id PHC at rest; PKCE on public clients |
| `SsoClient::process_ticket` | Must consume the ticket; HMAC request signing is `sso/sign.rs` (`RequestSign`) |
| `NonceManager` / `RefreshTokenManager` | `from_dao(Arc<SaTokenDao>)` |
| `SaStorageDistributedStorage` | `from_dao`；login wires `DistributedSessionManager` only if `with_distributed_manager` |
| `grant_repo()` on Manager | `#[deprecated]` — use `authz_service()` |

Dao has **no** `set_json`; use `set_object` / `get_object`. Configuration errors use `SaTokenError::ConfigError` (there is no `InvalidConfiguration`).

---

## 4. New modules (real paths)

- `sa-token-core/src/dao.rs` — storage funnel
- `sa-token-core/src/keys.rs` — `SaKeys`
- `sa-token-core/src/token_io.rs` — `read_token`, `apply_token_prefix`, `write_token_cookie`, `delete_token_cookie`
- `sa-token-core/src/service/` — `AuthService`, `AuthzService`
- `sa-token-core/src/stp_logic.rs` — `SaLogic`
- `sa-token-core/src/http_basic.rs` / `same_token.rs`
- `sa-token-core/src/oauth2/` / `sso/` directories
- `sa-token-core/src/cleanup/` — optional background cleanup (off by default)
- `sa-token-plugin-common` — shared plugin state
- `sa-token-adapter` — `scan`, `get_del`, `compare_and_swap`, `list_push`, `SaSerializer` / `SharedSerializer` (optional `fory`)
- `sa-token-core/src/codec.rs` — encode/decode helpers over the configured serializer

SSO API request signing lives under `sso/sign.rs` (`RequestSign`).

---

## 5. Storage capability matrix (documentation only)

| Capability | Memory | Redis | Database crate |
|------------|--------|-------|----------------|
| KV get/set/delete | yes | yes | yes (basic) |
| `get_del` / CAS / `set_if_absent` | yes | yes | **Unsupported** |
| `list_push` / `list_remove` | yes | yes | **Unsupported** |
| `scan` | yes | yes | **Unsupported** |

Do not use the database backend for nonce one-shot consume, online indexes, or multi-device lists until a later storage plan. This release does **not** extend `sa-token-storage-database` for those capabilities.

---

## 6. Suggested upgrade steps

1. Set every `sa-token-*` dependency to `0.2.0`.
2. Replace `*-core` imports with `sa-token-plugin-common` / plugin prelude.
3. Switch `StpUtil::init_manager` → `try_init_manager`.
4. Handle `TokenGenerator` / `OnlineManager` / JWT `Result`.
5. Set `auto_renew(true)` only if you need 0.1.x renewal.
6. Move public routes from `#[sa_ignore]` assumptions to `PathAuthConfig::exclude`.
7. If you need Bearer / custom prefixes or cookie writes, configure `token_prefix` / `is_write_cookie` explicitly.
8. Re-read OAuth2 client registration (hash secrets, PKCE) and SSO ticket consume.
9. Replace any `put_stp_logic` usage with `SaLogic::new` / `StpUtil::stp_logic` (old APIs are deprecated no-ops).
10. Optional: enable `fory` and `.serializer(...)` only if you need non-JSON storage encoding (see `doc/guide/storage.md`).
11. `cargo check --workspace` then `cargo clippy --workspace --lib`.

---

## 7. Help

- Site: `doc/` (VitePress), GitHub Pages base `/sa-token-rust/`
- Issues: https://github.com/sa-tokens/sa-token-rust/issues

---

<a id="简体中文"></a>
# 简体中文

## 1. 可能静默影响生产的行为

### 1.1 `auto_renew` 默认 `false`

0.1.x 读 token 可能写回 TTL。0.2.0 默认关闭，避免每次读取都写存储。需要旧行为时显式 `.auto_renew(true)`。

```rust
SaTokenConfig::builder()
    .storage(storage)
    .auto_renew(true)
    .renew_threshold(300)
    .try_build()?;
```

### 1.2 `is_read_*` 真正生效

`is_read_header` / `is_read_cookie` / `is_read_body` 现在会经 `token_io::read_token` 真正控制框架适配器的 token 提取。生产若只走 Header，不要关掉 `is_read_header`。

### 1.3 JWT

- 缺 / 空 `jwt_secret_key` 且使用 `TokenStyle::Jwt` → `try_build` / `TokenGenerator` 返回 `Err(SaTokenError::ConfigError)`（库路径不再 panic）。
- `jwt_fallback_on_error` 默认 **`false`**。JWT 失败不再偷偷变成 UUID。仅在理解风险时 `.jwt_fallback_on_error(true)`。

### 1.4 `#[sa_ignore]` 不跳过中间件

路径放行用 `PathAuthConfig::exclude`。该属性只跳过**宏插入**的校验。

### 1.5 在线用户是长连接 presence

`OnlineManager::new()` 仍是进程内。跨实例用 `with_distributed_online()`。HTTP 登录不会 `mark_online`。

### 1.6 `token_prefix`（存在）

`SaTokenConfig` / builder 上的可选字段：`.token_prefix("Bearer ")`。

- 读 token 时由 `token_io::apply_token_prefix` 应用。
- `None`（默认）仍会剥离开头的 `Bearer `，保持兼容。
- 空字符串在 `try_build` 时拒绝。

Token 的 Header/Cookie/query **键名**仍是 `token_name`（默认 `"sa-token"`）。二者不要混淆。

### 1.7 Cookie 写入：`is_write_cookie`（存在）

登录**不会**自动 `Set-Cookie`。写 Cookie 为可选开启：

```rust
SaTokenConfig::builder()
    .storage(storage)
    .is_write_cookie(true)
    .cookie_http_only(true)
    .try_build()?;
```

需要下发 Cookie 的 handler / 适配器须调用 `write_token_cookie`（登出用 `delete_token_cookie`）。`is_write_cookie` 为 `false`（默认）时，这些辅助函数为空操作。相关选项在 `TokenCookieConfig`（`domain`、`path`、`secure`、`same_site` 等）。

---

## 2. 已移除项

| 已移除 | 替代 |
|--------|------|
| `SaStorage::keys(pattern)` | `SaStorage::scan(pattern, cursor, limit)` 直到 `next_cursor == 0` |
| 服务中直接握 `SaStorage` | `SaTokenDao`（`set_object` / `get_object` / `take_string` / `cas` / `list_*`） |
| `sa-token-plugin-*-core` crate | `sa-token-plugin-common`（`SaTokenState`、rejection 辅助） |
| `PermissionChecker` / `RoleChecker`（若仍在 import） | `StpInterface` + `PermissionMatcher`，经 `AuthzService` |
| `FrameworkAdapter` | `sa_token_adapter::plugin::SaTokenPlugin` |
| `StpUtil::init_manager` 作为主路径 | `StpUtil::try_init_manager` → `Result`（`AlreadyInitialized` 可恢复） |
| `TokenGenerator::generate_*` 直接返回 `TokenValue` | `SaTokenResult<TokenValue>` |
| `OnlineManager` 返回 `bool`/`usize` 且无 I/O 错误 | `SaTokenResult<_>` |
| 进程内 OAuth2/SSO `HashMap` 存储 | Dao 后端存储 |
| `put_stp_logic` / 全局 SaLogic 注册表 | **废弃空操作** — 改用 `SaLogic::new(login_type, manager)` 或 `StpUtil::stp_logic`（可克隆门面；无进程级表） |

### 2.1 Import 对照（`*-core` → common）

```rust
// 0.1.x
// use sa_token_plugin_axum_core::SaTokenState;

// 0.2.0 — 从各 plugin 再导出，或：
use sa_token_plugin_common::SaTokenState;
use sa_token_plugin_axum::*; // 亦有 `pub use sa_token_plugin_common as common`
```

Actix / Rocket / Salvo / Gotham / Ntex 门面同样从 `sa-token-plugin-common` 再导出 `SaTokenState`。不要再依赖 `sa-token-plugin-*-core`。

---

## 3. 签名 / API 变更

| API | 0.2.0 |
|-----|--------|
| `StpUtil::try_init_manager` / `try_get_manager` | `SaTokenResult`（`AlreadyInitialized` / `NotInitialized`） |
| `SaTokenConfigBuilder::try_build` / `try_build_config` | JWT + storage 检查返回 `Err` |
| `SaTokenConfigBuilder::serializer` | 注入 `SharedSerializer`（默认 JSON；可选 `fory`） |
| `SaTokenConfigBuilder::build` | 缺 storage 仍会 panic；库代码请用 `try_build` |
| `TokenGenerator::generate_with_login_id` | `SaTokenResult<TokenValue>` |
| `router::extract_token(req, token_name)` | **未变**（`&str` 名称，不是 `&SaTokenConfig`） |
| 适配器读 token | 优先 `token_io::read_token(req, &config)` |
| `SaTokenEventBus` | `DispatchMode::{Sequential, Concurrent, Detached}` + listener 超时 |
| `AuthService` / `AuthzService` | 登录/登出/授权经 service，不经 Manager 内部 |
| `SaTokenContext` | 请求级；无 `request` 字段 — 宏使用 `RequestAuthMeta` |
| 多账号 | `login_type` + `SaLogic`（无进程级 logic 表） |
| OAuth2 client secret | 落库 Argon2id PHC；公有客户端 PKCE |
| `SsoClient::process_ticket` | 必须消费票据；HMAC 请求签名在 `sso/sign.rs`（`RequestSign`） |
| `NonceManager` / `RefreshTokenManager` | `from_dao(Arc<SaTokenDao>)` |
| `SaStorageDistributedStorage` | `from_dao`；仅在 `with_distributed_manager` 时登录接线 `DistributedSessionManager` |
| Manager 上的 `grant_repo()` | `#[deprecated]` — 请用 `authz_service()` |

Dao **没有** `set_json`；用 `set_object` / `get_object`。配置错误类型是 `SaTokenError::ConfigError`，没有 `InvalidConfiguration`。

---

## 4. 新模块（真实路径）

- `sa-token-core/src/dao.rs` — 存储漏斗
- `sa-token-core/src/keys.rs` — `SaKeys`
- `sa-token-core/src/token_io.rs` — `read_token`、`apply_token_prefix`、`write_token_cookie`、`delete_token_cookie`
- `sa-token-core/src/service/` — `AuthService`、`AuthzService`
- `sa-token-core/src/stp_logic.rs` — `SaLogic`
- `sa-token-core/src/http_basic.rs` / `same_token.rs`
- `sa-token-core/src/oauth2/` / `sso/` 目录
- `sa-token-core/src/cleanup/` — 可选后台清理（默认关）
- `sa-token-plugin-common` — 共享插件状态
- `sa-token-adapter` — `scan`、`get_del`、`compare_and_swap`、`list_push`、`SaSerializer` / `SharedSerializer`（可选 `fory`）
- `sa-token-core/src/codec.rs` — 基于配置序列化器的编解码辅助

SSO 的 API 请求签名在 `sso/sign.rs`（`RequestSign`）。

---

## 5. 存储能力矩阵（仅文档）

| 能力 | Memory | Redis | Database crate |
|------|--------|-------|----------------|
| KV get/set/delete | 是 | 是 | 是（基本） |
| `get_del` / CAS / `set_if_absent` | 是 | 是 | **不支持** |
| `list_push` / `list_remove` | 是 | 是 | **不支持** |
| `scan` | 是 | 是 | **不支持** |

在后续存储专项完成前，不要用 database 后端做 nonce 一次性消费、在线索引或多端列表。本版本**不扩展** `sa-token-storage-database` 的这些能力。

---

## 6. 建议升级步骤

1. 所有 `sa-token-*` 依赖升到 `0.2.0`。
2. `*-core` import 改为 `sa-token-plugin-common` / 插件 prelude。
3. `StpUtil::init_manager` → `try_init_manager`。
4. 处理 `TokenGenerator` / `OnlineManager` / JWT 的 `Result`。
5. 仅在需要 0.1.x 续期时设 `auto_renew(true)`。
6. 公开路由从「以为 `#[sa_ignore]` 能放行」改为 `PathAuthConfig::exclude`。
7. 需要 Bearer / 自定义前缀或写 Cookie 时，显式配置 `token_prefix` / `is_write_cookie`。
8. 重读 OAuth2 客户端注册（哈希密钥、PKCE）与 SSO 票据消费。
9. 任何 `put_stp_logic` 用法改为 `SaLogic::new` / `StpUtil::stp_logic`（旧 API 为废弃空操作）。
10. 可选：仅在需要非 JSON 存储编码时启用 `fory` 并 `.serializer(...)`（见 `doc/zh/guide/storage.md`）。
11. `cargo check --workspace`，再 `cargo clippy --workspace --lib`。

---

## 7. 帮助

- 站点：`doc/`（VitePress），GitHub Pages base `/sa-token-rust/`
- Issues：https://github.com/sa-tokens/sa-token-rust/issues
