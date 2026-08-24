# StpUtil

[English](/guide/stp-util.md) | 中文

`StpUtil` 是进程内全局 `SaTokenManager` 的静态门面。Web 插件的 `SaTokenState` / `SaTokenConfig::try_build` 会在启动时调用 `try_init_manager`；业务代码优先用 `try_*` API，避免未初始化时 panic。

## 何时使用

- 在请求处理函数、宏展开后的检查、后台任务里调用登录 / 鉴权。
- 需要「无参数」读写当前请求上下文（中间件已注入 `SaTokenContext`）。

## 初始化

```rust
use sa_token_core::{SaTokenConfig, SaTokenError, StpUtil};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(7200)
    .try_build()?; // 内部会 try_init_manager；已初始化则打 warn 并返回本 Manager

// 库代码若自行持有 Manager：
match StpUtil::try_init_manager(manager.clone()) {
    Ok(()) => {}
    Err(SaTokenError::AlreadyInitialized) => {}
    Err(e) => return Err(e),
}

let mgr = StpUtil::try_get_manager()?; // 未初始化 → SaTokenError::NotInitialized
```

| API | 行为 |
|-----|------|
| `try_init_manager` | 成功 / `AlreadyInitialized`（不 panic） |
| `try_get_manager` | 成功 / `NotInitialized` |
| `init_manager` | 已废弃；失败会 panic |
| `is_login` | **未初始化时返回 `false`**（不报错） |
| `event_bus()` | `Option<&SaTokenEventBus>`；未初始化为 `None` |
| `register_listener` | **同步**；未初始化时静默跳过（不要 `.await`） |

插件路径：`SaTokenState::builder().storage(...).build()` 同样会完成全局初始化。

## LoginId

登录 ID 通过 `LoginId` trait 接受：`&str` / `String`，以及 `i32` / `i64` / `u32` / `u64` 等整数。内部统一为字符串键。

```rust
let t1 = StpUtil::login("user_10001").await?;
let t2 = StpUtil::login(10001).await?;
```

## 登录族与 `login_type`

```rust
use serde_json::json;

// 始终写入默认 login_type（"default"），不会跟随请求上下文
let token = StpUtil::login("10001").await?;
let token = StpUtil::login_with_extra("10001", json!({"ip": "10.0.0.1"})).await?;

// 显式指定非默认账号体系
let token = StpUtil::login_with_type("10001", "admin").await?;
```

**注意：** `login` / `login_with_extra` 固定登录到 **default** 账号体系，**不会**走 `resolve_login_type`。非 default 请用 `login_with_type`、`TokenBuilder`，或绑定 [`SaLogic`](./multi-account.md)。

其余多数短方法（`kick_out`、`get_session`、`disable`、`has_permission` 等）在有请求上下文时优先用当前 `login_type`，否则回落 `default`。显式 `*_with_type` 不会猜测。

## TokenBuilder

链式登录；结束时必须 `.login(None)`（`None` 用构建器里的 id，`Some(id)` 可覆盖）。

```rust
use chrono::{Duration, Utc};
use serde_json::json;

let token = StpUtil::builder("10001")
    .login_type("admin")
    .device("pc")
    .extra_data(json!({"channel": "web"}))
    .nonce("once-abc")                           // 需配置 enable_nonce
    .expire_at(Utc::now() + Duration::hours(2))  // 绝对过期
    // .expire_at_unix(1_700_000_000)            // 或 Unix 秒
    .login(None)
    .await?;
```

`expire_time(...)` 仍可作为 `expire_at` 的 **废弃别名** 编译；新代码请用 `expire_at` / `expire_at_unix`。

多账号细节见 [多账号与终端](./multi-account.md)。

## 登出与踢人

```rust
StpUtil::logout(&token).await?;
StpUtil::logout_current().await?;
StpUtil::logout_by_login_id("10001").await?; // 当前 login_type，否则 default

StpUtil::kick_out("10001").await?;
StpUtil::kick_out_with_type("admin", "10001").await?;
StpUtil::kick_out_by_token(&token).await?;   // 按单个 token 踢下线
```

`logout` 正常结束会话；`kick_out` / `kick_out_by_token` 标记 KickOut，便于业务区分强制下线。

## Token-Session

按 token 维度的 Session（与按 `login_id` 的账号 Session 分开）：

```rust
let mut sess = StpUtil::get_token_session(&token).await?;
// 中间件注入后也可用：StpUtil::get_token_session_current().await?;

sess.set("cart_id", "c-9")?;
StpUtil::save_token_session(&token, &sess).await?;
StpUtil::delete_token_session(&token).await?;
```

相关配置：`right_now_create_token_session`、`token_session_check_login`、`is_logout_keep_token_session`。

## 封禁（含按类型）

```rust
// 使用当前请求 login_type，否则 default
StpUtil::disable("10001", 86400).await?;
StpUtil::disable_level("10001", "comment", 2, 3600).await?;

// 显式账号体系
StpUtil::disable_with_type("admin", "10001", 86400).await?;

let level = StpUtil::get_disable_level("10001", "comment").await?;
StpUtil::check_disable("10001").await?;
StpUtil::untie_disable("10001", "comment").await?;
```

更多封禁 / 二级认证 / Same-Token 等见 [安全能力](./security-features.md)。

## 当前请求上下文

中间件 / Layer 跑完 `run_auth_flow` 后，可在 handler 内无参数调用：

```rust
let token = StpUtil::get_token_value()?;
let login_id = StpUtil::get_login_id_as_string().await?;
let id_i64 = StpUtil::get_login_id_as_long().await?; // 非数字 → LoginIdNotNumber

// 弱校验：仅看上下文是否有 token 字符串
if StpUtil::is_login_current() { /* ... */ }

// 强校验：上下文 token 且存储仍有效
StpUtil::check_login_current_async().await?;
```

`#[sa_check_login]` 展开为异步存储校验（`check_login_current_async`）；使用该宏的 handler 必须是 `async`。

## 登录状态

```rust
// 未初始化或无效 token → false
let ok = StpUtil::is_login(&token).await;
let ok = StpUtil::is_login_by_login_id("10001").await;
```

## 权限与角色

`has_*` 返回 `bool`（未初始化为 `false`）；`check_*` 失败返回 `Err`。**不要**对 `has_*` 使用 `?`。

```rust
StpUtil::set_permissions("10001", vec!["user:add".into(), "user:*".into()]).await?;
StpUtil::set_roles("10001", vec!["admin".into()]).await?;

if StpUtil::has_permission("10001", "user:delete").await { /* ... */ }
StpUtil::check_permission("10001", "user:add").await?;

StpUtil::has_all_permissions("10001", &["user:add", "user:list"]).await;
StpUtil::has_any_permission("10001", &["user:add", "user:delete"]).await;
StpUtil::check_role("10001", "admin").await?;
```

通配与宏见 [权限匹配与宏](./permission-matching.md)。

## 事件总线

```rust
use std::sync::Arc;
use sa_token_core::SaTokenListener;

// 推荐：构建期注册
SaTokenConfig::builder()
    .storage(storage)
    .register_listener(Arc::new(MyListener))
    .try_build()?;

// 运行期
if let Some(bus) = StpUtil::event_bus() {
    bus.register(Arc::new(MyListener));
}
StpUtil::register_listener(Arc::new(MyListener)); // 未 init 则 no-op；非异步
```

完整钩子与 `DispatchMode` 见 [事件监听](./event-listener.md)。

## 相关链接

- [快速入门](./quick-start.md)
- [多账号与终端](./multi-account.md)
- [路径鉴权](./path-auth.md)
- [权限匹配与宏](./permission-matching.md)
- [安全能力](./security-features.md)
- [错误参考](/zh/reference/error-reference.md)
