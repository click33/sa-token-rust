# sa-token-macro

Procedural macros for sa-token-rust.

## Features

- 🎯 **Annotation Style**: Attribute-macro syntax
- ✅ **Compile-time Checking**: Catch errors before runtime
- 🔧 **Easy to Use**: Decorator-style authentication
- 📝 **Comprehensive**: All authentication scenarios covered

## Installation

```toml
[dependencies]
sa-token-macro = "0.2.0"
sa-token-core = "0.2.0"
```

## Macros

### Login Check

```rust
use sa_token_macro::sa_check_login;

#[sa_check_login]
async fn protected_route() -> &'static str {
    "This route requires login"
}
```

### Permission Check

```rust
use sa_token_macro::sa_check_permission;

#[sa_check_permission("user:list")]
async fn list_users() -> &'static str {
    "User list"
}
```

### Role Check

```rust
use sa_token_macro::sa_check_role;

#[sa_check_role("admin")]
async fn admin_panel() -> &'static str {
    "Admin panel"
}
```

### Multiple Permissions (AND)

```rust
use sa_token_macro::sa_check_permissions_and;

#[sa_check_permissions_and("user:list", "user:edit")]
async fn manage_users() -> &'static str {
    "Manage users"
}
```

### Multiple Permissions (OR)

```rust
use sa_token_macro::sa_check_permissions_or;

#[sa_check_permissions_or("user:view", "user:list")]
async fn view_users() -> &'static str {
    "View users"
}
```

### `#[sa_ignore]`

Skips StpUtil checks inserted by other `#[sa_check_*]` macros on this item.
**Does not** skip framework middleware. For public HTTP routes:

```rust
use sa_token_core::router::PathAuthConfig;
let cfg = PathAuthConfig::new()
    .include(vec!["/**".into()])
    .exclude(vec!["/health".into()]);
```

See [doc/guide/permission-matching.md](../doc/guide/permission-matching.md) and
[doc/guide/path-auth.md](../doc/guide/path-auth.md).

## Permission Matching Rules

See [doc/guide/permission-matching.md](../doc/guide/permission-matching.md) for detailed rules.

## Author

**金书记**

## License

Licensed under either of Apache-2.0 or MIT.
