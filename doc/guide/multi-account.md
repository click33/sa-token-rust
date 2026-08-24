# Multi-account

English | [中文](/zh/guide/multi-account.md)

Use `login_type` to isolate account systems (for example `admin` vs `user`): token mappings, sessions, permission and role keys. Device identity is a `device` string and participates in replace / kick policies.

This page is self-contained for the 0.2 APIs — no external long-form docs required.

## What login_type means

- Default is the constant `default` (empty string normalizes to default).
- Different `login_type` values do not share `login:token`, account session, or grant keys.
- If the request context sets a current `login_type`, most `StpUtil` APIs prefer it; otherwise they fall back to default.

## Login with TokenBuilder

```rust
use sa_token_core::StpUtil;

let admin_token = StpUtil::builder("42")
    .login_type("admin")
    .device("pc")
    .login(None::<String>)
    .await?;

let user_token = StpUtil::builder("42")
    .login_type("user")
    .device("app")
    .login(None::<String>)
    .await?;
```

Same `login_id`, different `login_type` → two login states. You can also chain `extra_data` / `nonce` / `expire_time`.

Equivalent lower level: `LoginRequest::new(...).login_type(...).device(...)` into the Manager.

## SaLogic (type-bound facade)

```rust
let manager = StpUtil::try_get_manager()?;
let admin = manager.stp_logic("admin"); // or SaLogic::new("admin", manager)

let token = admin.login("42").await?;
admin.login_with_device("42", Some("pc".into()), None).await?;
admin.check_permission("42", "user:delete").await?;
admin.logout(&token).await?;
admin.kick_out("42").await?;
```

`SaLogic` pins every call to a fixed `login_type` so you need not pass `*_with_type` each time.

## device

- Labels the terminal (`pc` / `app` / `ws`), stored on `TokenInfo` and the terminal list.
- Together with `is_concurrent` / `replaced_range`, controls whether replace kicks the whole account or only the same device.
- Macro: `#[sa_check_terminal("pc")]` requires the current token’s device to match.

## Grants and kick (typed)

```rust
StpUtil::set_permissions_with_type("admin", "42", vec!["user:delete".into()]).await?;
StpUtil::has_permission_with_type("admin", "42", "user:delete").await?;

StpUtil::kick_out_with_type("admin", "42").await?;
StpUtil::get_token_by_login_id_with_type("admin", "42").await?;
```

Short methods without `_with_type` use “current context login_type, else default”.

## Related

- [StpUtil](/guide/stp-util.md)
- [Path auth](/guide/path-auth.md)
- [Permissions and macros](/guide/permission-matching.md)
