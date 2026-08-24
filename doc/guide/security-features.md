# Security features

English | [中文](/zh/guide/security-features.md)

Nonce, Refresh, secondary auth (Safe), Disable, Same-Token, request Sign, TempToken, HTTP Basic, and matching proc macros.

## Nonce (anti-replay)

Enable in config, then bind a one-shot nonce at login:

```rust
SaTokenConfig::builder()
    .enable_nonce(true)
    .nonce_timeout(60)
    // ...
```

```rust
use sa_token_core::NonceManager;

let nonce_mgr = NonceManager::from_dao(manager.dao().clone(), 60);
let nonce = nonce_mgr.generate();
nonce_mgr.store(&nonce, "user_1").await?;
nonce_mgr.validate_and_consume(&nonce, "user_1").await?;

// or pass at login
StpUtil::builder("user_1").nonce(nonce).login(None::<String>).await?;
```

## Refresh token

When enabled, the login pipeline can issue a refresh token. On refresh, sa-token **atomically updates** the token body, reverse mapping, `login:token`, and multi-device index, then deletes the old access token.

```rust
SaTokenConfig::builder()
    .enable_refresh_token(true)
    .refresh_token_timeout(2_592_000)
    // ...
```

```rust
use sa_token_core::RefreshTokenManager;

let refresh = RefreshTokenManager::from_dao(manager.dao().clone());
// or from_storage(storage, config); refresh string usually comes from login
let (new_access, login_id) = refresh.refresh_access_token(&refresh_token).await?;
```

Also: `revoke_all_for_user(login_type, login_id)`.

## Safe (secondary auth)

Open a short safe window before sensitive actions:

```rust
StpUtil::open_safe("transfer", 300).await?; // seconds; current request token
StpUtil::check_safe("transfer").await?;
```

Macro: `#[sa_check_safe("transfer")]`.

## Disable

```rust
StpUtil::disable("user_1", 86400).await?;           // default service
StpUtil::disable_level("user_1", "comment", 2, 3600).await?;
StpUtil::check_disable("user_1").await?;
StpUtil::untie_disable("user_1", "").await?;
```

Macro: `#[sa_check_disable]` (optional service / level — see macro docs).

## Same-Token

Shared secret for cluster / gateway-to-service calls. Default header `SA-SAME-TOKEN`. Current and previous values (grace) are both accepted.

```rust
let t = StpUtil::get_same_token().await?;
StpUtil::check_same_token(&t).await?;
let t2 = StpUtil::refresh_same_token().await?;
```

Macro: `#[sa_check_same_token]` (reads the request header and checks).

## Sign

With `sign_secret_key` (and optional `sign_window_secs`):

```rust
use std::collections::BTreeMap;

let mut params = BTreeMap::new();
params.insert("userId".into(), "42".into());
let signed = StpUtil::sign_params(params).await?; // timestamp / nonce / sign
StpUtil::check_sign(&signed).await?;
```

Lower-level type: `RequestSign` (optional `with_dao` for nonce dedup).

## TempToken

Short-lived business tokens (default namespace):

```rust
let t = StpUtil::create_temp_token("reset:user_1", 300).await?;
let record = StpUtil::parse_temp_token(&t).await?;
StpUtil::delete_temp_token(&t).await?;
```

Or `TempTokenManager::new(dao)` with an explicit namespace.

## HTTP Basic

```rust
use sa_token_core::http_basic;

http_basic::check("sa-token", "admin:secret")?; // Authorization: Basic ...
```

Macros:

```rust
#[sa_check_http_basic("admin:secret")]
async fn admin_only() { /* ... */ }

#[sa_check_http_basic(account = "admin:secret", realm = "sa-token")]
async fn with_realm() { /* ... */ }
```

## Related

- [JWT](/guide/jwt.md)
- [StpUtil](/guide/stp-util.md)
- [Error reference](/reference/error-reference.md)
