# 多账号体系

[English](/guide/multi-account.md) | 中文

用 `login_type` 隔离不同账号体系（例如 `admin` 与 `user`）的 token 映射、Session、权限与角色键空间。设备标识用 `device`（字符串），参与顶号范围等策略。

本页自洽说明 0.2 API，不依赖外部长文。

## login_type 是什么

- 默认值为常量 `default`（空串也会归一到默认）。
- 不同 `login_type` 的 `login:token`、账号 Session、权限/角色键互不覆盖。
- 请求上下文里若设置了当前 `login_type`，多数**非登录** `StpUtil` API 会优先用它；否则回落默认。
- `StpUtil::login` / `login_with_extra` **始终**使用 **default**，不会跟随请求上下文。其他体系请用 `login_with_type`、`TokenBuilder` 或 `SaLogic`。

## TokenBuilder 登录

```rust
use chrono::{Duration, Utc};
use sa_token_core::StpUtil;

let admin_token = StpUtil::builder("42")
    .login_type("admin")
    .device("pc")
    .expire_at(Utc::now() + Duration::hours(8))
    .login(None::<String>)
    .await?;

let user_token = StpUtil::builder("42")
    .login_type("user")
    .device("app")
    .login(None::<String>)
    .await?;
```

同一 `login_id`、不同 `login_type` 是两套登录态。也可链式设置 `extra_data` / `nonce` / `expire_at` / `expire_at_unix`（`expire_time` 为废弃别名）。

等价底层：`LoginRequest::new(...).login_type(...).device(...)` 再交给 Manager。

## SaLogic（绑定类型的门面）

0.2 **没有**进程级 SaLogic 注册表。`SaLogic` 是廉价 `Clone` 门面，内部持有 `SaTokenManager` 克隆与固定 `login_type`。`put_stp_logic` / `remove_stp_logic` 仍保留为废弃空操作，仅兼容旧源码。

```rust
use sa_token_core::{SaLogic, StpUtil};

// 推荐：返回 Result 的工厂
let admin = StpUtil::stp_logic("admin")?;

// 或从 Manager 克隆
let manager = StpUtil::try_get_manager()?;
let admin = manager.stp_logic("admin");
// 亦可：SaLogic::new("admin", manager.as_ref().clone())

let token = admin.login("42").await?;
admin.login_with_device("42", Some("pc".into()), None).await?;
admin.check_permission("42", "user:delete").await?;
admin.logout(&token).await?;
admin.kick_out("42").await?;
```

`SaLogic` 把所有操作钉在固定 `login_type` 上，避免每次手写 `*_with_type`。

## device

- 表示终端类型（如 `pc` / `app` / `ws`），写入 `TokenInfo` 与终端列表。
- 与 `is_concurrent` / `replaced_range` 等配置一起决定「顶号」是整账号还是同设备。
- 宏：`#[sa_check_terminal("pc")]` 可要求当前 token 的设备匹配。

## 权限与踢人（按类型）

```rust
StpUtil::set_permissions_with_type("admin", "42", vec!["user:delete".into()]).await?;

// has_* 返回 bool，不能用 ?
if StpUtil::has_permission_with_type("admin", "42", "user:delete").await {
    // ...
}

StpUtil::kick_out_with_type("admin", "42").await?;
StpUtil::get_token_by_login_id_with_type("admin", "42").await?;
StpUtil::disable_with_type("admin", "42", 3600).await?;
```

无 `_with_type` 的短方法使用「当前上下文 login_type，否则 default」（`login` / `login_with_extra` 除外，见上文）。

## 相关链接

- [StpUtil](/zh/guide/stp-util.md)
- [路径鉴权](/zh/guide/path-auth.md)
- [权限匹配与宏](/zh/guide/permission-matching.md)
- [安全能力](/zh/guide/security-features.md)
