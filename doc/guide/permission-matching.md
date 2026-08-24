# Permissions and macros

English | [中文](/zh/guide/permission-matching.md)

Permissions default to **Ant segment wildcards** (`AntPermissionMatcher`); roles default to **exact match** (`ExactMatcher`). Set `role_wildcard(true)` to use Ant for roles too. Handler-side `#[sa_check_*]` macros insert `StpUtil` checks.

## Ant vs Exact

Permissions are split on `:`:

| Owned pattern | Covers | Does not cover |
|---------------|--------|----------------|
| `user:read` | `user:read` | anything else |
| `*` / `**` | any permission | — |
| `user:*` | `user:add` | `user`, `user:add:vip` |
| `user:**` | `user`, `user:add`, `user:add:vip` | `userx` |
| `user:*:read` | `user:add:read` | `user:read` |

Roles must match exactly unless you enable wildcards:

```rust
SaTokenConfig::builder()
    .storage(storage)
    .role_wildcard(true) // roles also use AntPermissionMatcher
    .try_build()?;
```

You can also inject a custom `PermissionMatcher` via `with_permission_matcher` / `with_role_matcher` on the manager.

## has_* vs check_*

| Family | Returns | Typical use |
|--------|---------|-------------|
| `has_permission` / `has_role` / `has_all_*` / `has_any_*` | `bool` (`false` if not init) | Branches, UI flags |
| `check_permission` / `check_role` / `check_all_*` / `check_any_*` | `SaTokenResult<()>` | Guards; fail upward |

```rust
StpUtil::set_permissions("10001", vec!["user:*".into()]).await?;

assert!(StpUtil::has_permission("10001", "user:add").await);
StpUtil::check_permission("10001", "user:delete").await?; // denied → Err

StpUtil::has_all_permissions("10001", &["user:add", "user:list"]).await;
StpUtil::has_any_permission("10001", &["admin:all", "user:add"]).await;
```

Aliases: `has_permissions_and` ≡ `has_all_permissions`; `has_permissions_or` ≡ `has_any_permission`.

## Macros `sa_check_*`

The target must be an `async fn` returning `Result<T, E>` where `E: From<SaTokenError>`. Macros insert the matching `StpUtil` call at the start of the function (needs request context / current login id).

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

Other macros (see security / multi-account guides):

- `#[sa_check_or(...)]` — permission or role combinations
- `#[sa_check_safe]` / `#[sa_check_disable]`
- `#[sa_check_terminal("pc")]`
- `#[sa_check_http_basic("user:pass")]`
- `#[sa_check_same_token]`

## Real semantics of `#[sa_ignore]`

```rust
#[sa_ignore]
async fn public_info() -> Result<&'static str, SaTokenError> {
    Ok("ok")
}
```

- **Does**: skip inserting any `StpUtil` macro checks on this item.
- **Does not**: bypass `SaTokenLayer` / `SaTokenMiddleware`. Anonymous HTTP paths need `PathAuthConfig::exclude`.
- **Conflict**: cannot combine `#[sa_ignore]` with `#[sa_check_*]` on the same function (compile error).

## Related

- [Path auth](./path-auth.md)
- [StpUtil](./stp-util.md)
- [Security features](./security-features.md)
