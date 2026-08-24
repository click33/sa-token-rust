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
| `register_listener` | 未初始化时静默跳过 |

插件路径：`SaTokenState::builder().storage(...).build()` 同样会完成全局初始化。

## LoginId

登录 ID 通过 `LoginId` trait 接受：`&str` / `String`，以及 `i32` / `i64` / `u32` / `u64` 等整数。内部统一为字符串键。

```rust
let t1 = StpUtil::login("user_10001").await?;
let t2 = StpUtil::login(10001).await?;
```

## 登录族

```rust
// 默认 login_type
let token = StpUtil::login("10001").await?;

// 指定账号体系
let token = StpUtil::login_with_type("10001", "admin").await?;

// 额外 JSON（常用于 JWT claims / 审计字段）
use serde_json::json;
let token = StpUtil::login_with_extra("10001", json!({"ip": "10.0.0.1"})).await?;
```

## TokenBuilder

链式登录；结束时必须 `.login(None)`（`None` 用构建器里的 id，`Some(id)` 可覆盖）。

```rust
use serde_json::json;

let token = StpUtil::builder("10001")
    .login_type("admin")
    .device("pc")
    .extra_data(json!({"channel": "web"}))
    .nonce("once-abc")          // 需配置 enable_nonce
    // .expire_time(some_utc)   // 绝对过期
    .login(None)
    .await?;
```

多账号细节见 [多账号与终端](./multi-account.md)。

## 登出与踢人

```rust
StpUtil::logout(&token).await?;                 // 按 token
StpUtil::logout_current().await?;               // 当前请求上下文
StpUtil::logout_by_login_id("10001").await?;    // 按账号（当前 login_type）

StpUtil::kick_out("10001").await?;              // 踢下线（标记 KickOut）
StpUtil::kick_out_with_type("admin", "10001").await?;
```

`logout` 与 `kick_out` 语义不同：前者正常结束会话，后者标记为被踢，便于业务区分。

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

## 登录状态

```rust
// 未初始化或无效 token → false
let ok = StpUtil::is_login(&token).await;
let ok = StpUtil::is_login_by_login_id("10001").await;
```

## 权限与角色

`has_*` 返回 `bool`（未初始化为 `false`）；`check_*` 失败返回 `Err`。

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
StpUtil::register_listener(Arc::new(MyListener)); // 未 init 则 no-op
```

完整钩子与 `DispatchMode` 见 [事件监听](./event-listener.md)。

## 相关链接

- [快速入门](./quick-start.md)
- [路径鉴权](./path-auth.md)
- [权限匹配与宏](./permission-matching.md)
- [错误参考](/zh/reference/error-reference.md)
