# 权限匹配与宏

[English](/guide/permission-matching.md) | 中文

权限串默认用 **Ant 分段通配**（`AntPermissionMatcher`）；角色默认 **精确匹配**（`ExactMatcher`）。可用 `role_wildcard(true)` 让角色也走 Ant。处理器侧用 `#[sa_check_*]` 宏插入 `StpUtil` 检查。

## Ant vs Exact

权限按 `:` 分段：

| 已持有模式 | 能覆盖 | 不能覆盖 |
|------------|--------|----------|
| `user:read` | `user:read` | 其他 |
| `*` / `**` | 任意权限 | — |
| `user:*` | `user:add` | `user`、`user:add:vip` |
| `user:**` | `user`、`user:add`、`user:add:vip` | `userx` |
| `user:*:read` | `user:add:read` | `user:read` |

角色默认必须字符串全等；开启通配：

```rust
SaTokenConfig::builder()
    .storage(storage)
    .role_wildcard(true) // 角色也用 AntPermissionMatcher
    .try_build()?;
```

也可在 Manager 上注入自定义 `PermissionMatcher`（见 `with_permission_matcher` / `with_role_matcher`）。

## has_* vs check_*

| 系列 | 返回值 | 典型用途 |
|------|--------|----------|
| `has_permission` / `has_role` / `has_all_*` / `has_any_*` | `bool`（未 init → `false`） | 分支、UI 开关 |
| `check_permission` / `check_role` / `check_all_*` / `check_any_*` | `SaTokenResult<()>` | 守卫；失败向上抛 |

```rust
StpUtil::set_permissions("10001", vec!["user:*".into()]).await?;

assert!(StpUtil::has_permission("10001", "user:add").await);
StpUtil::check_permission("10001", "user:delete").await?; // 无权限 → Err

StpUtil::has_all_permissions("10001", &["user:add", "user:list"]).await;
StpUtil::has_any_permission("10001", &["admin:all", "user:add"]).await;
```

别名：`has_permissions_and` ≡ `has_all_permissions`；`has_permissions_or` ≡ `has_any_permission`。

## 宏 `sa_check_*`

目标函数必须是 `async fn`，且返回 `Result<T, E>`（`E: From<SaTokenError>`）。宏在函数入口插入对应 `StpUtil` 调用（依赖请求上下文 / 当前 login_id）。

```rust
use sa_token_macro::{
    sa_check_login, sa_check_permission, sa_check_role,
    sa_check_permissions_and, sa_check_permissions_or,
    sa_check_roles_and, sa_check_roles_or,
};

#[sa_check_login]
async fn profile() -> Result<String, SaTokenError> {
    Ok(StpUtil::get_login_id_as_string().await?)
}

#[sa_check_permission("user:delete")]
async fn delete_user() -> Result<(), SaTokenError> { Ok(()) }

#[sa_check_role("admin")]
async fn admin_only() -> Result<(), SaTokenError> { Ok(()) }

#[sa_check_permissions_and("user:add", "user:edit")]
async fn edit() -> Result<(), SaTokenError> { Ok(()) }

#[sa_check_permissions_or("user:add", "admin:all")]
async fn add_or_admin() -> Result<(), SaTokenError> { Ok(()) }

#[sa_check_roles_and("admin", "auditor")]
async fn dual_role() -> Result<(), SaTokenError> { Ok(()) }

#[sa_check_roles_or("admin", "ops")]
async fn admin_or_ops() -> Result<(), SaTokenError> { Ok(()) }
```

其他常用宏（细节见安全 / 多账号指南）：

- `#[sa_check_or(...)]` — 权限或角色组合
- `#[sa_check_safe]` / `#[sa_check_disable]`
- `#[sa_check_terminal("pc")]`
- `#[sa_check_http_basic("user:pass")]`
- `#[sa_check_same_token]`

## `#[sa_ignore]` 真实语义

```rust
#[sa_ignore]
async fn public_info() -> Result<&'static str, SaTokenError> {
    Ok("ok")
}
```

- **会做**：本 item **不插入**任何 `StpUtil` 宏检查。
- **不会做**：跳过 `SaTokenLayer` / `SaTokenMiddleware`。匿名 HTTP 路径必须用 `PathAuthConfig::exclude`。
- **冲突**：同一函数不能同时写 `#[sa_ignore]` 与 `#[sa_check_*]`（编译期报错）。

## 相关链接

- [路径鉴权](./path-auth.md)
- [StpUtil](./stp-util.md)
- [安全特性](./security-features.md)
