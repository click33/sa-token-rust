# Migrate to 0.2.0

[中文](/zh/guide/migration-0.2.md)

Use this page when upgrading from 0.1.x to 0.2.0. The full bilingual document also lives at the repository root: [MIGRATION_0.2.md](https://github.com/sa-tokens/sa-token-rust/blob/main/MIGRATION_0.2.md).

Design is inspired by Dromara sa-token; this tree is an independent implementation (MIT OR Apache-2.0). See `NOTICE`.

## Behaviour that can silently change production

### `auto_renew` defaults to `false`

In 0.1.x a token read could rewrite TTL. Since 0.2.0 the default is off to avoid a storage write on every read. Opt in only if you need the old behaviour:

```rust
SaTokenConfig::builder()
    .storage(storage)
    .auto_renew(true)
    .renew_threshold(300)
    .try_build()?;
```

### `is_read_*` actually applies

`is_read_header` / `is_read_cookie` / `is_read_body` control extraction through `token_io::read_token`. Do not disable `is_read_header` if clients send the token in a header.

### JWT

- Missing / empty `jwt_secret_key` with `TokenStyle::Jwt` → `Err(SaTokenError::ConfigError)` from `try_build` / `TokenGenerator` (no library-path panic).
- `jwt_fallback_on_error` defaults to `false`. A failed JWT no longer silently becomes a UUID.

### `#[sa_ignore]` does not skip middleware

Public routes must be listed in `PathAuthConfig::exclude`. The attribute only skips the macro-inserted check; it does not bypass Layer / Middleware.

### Online users are presence

`OnlineManager::new()` stays process-local. Cross-instance presence requires `with_distributed_online()`. HTTP login does not call `mark_online`.

### `token_prefix` (exists)

Optional config: `.token_prefix("Bearer ")`.

- Applied by `token_io::apply_token_prefix` when reading tokens.
- `None` (default) still strips a leading `Bearer `.
- Empty string is rejected at `try_build` time.

The token **key name** remains `token_name` (default `"sa-token"`). Do not confuse name and prefix.

### Cookie writes: `is_write_cookie` (exists)

Login does not automatically `Set-Cookie`. To emit cookies:

```rust
SaTokenConfig::builder()
    .storage(storage)
    .is_write_cookie(true)
    .cookie_http_only(true)
    .try_build()?;
```

Call `write_token_cookie` on the response path; use `delete_token_cookie` on logout. When the flag is `false` (default), both helpers are no-ops.

### Pluggable storage encoding (`SaSerializer`)

Storage payloads (token info, sessions, nonce, OAuth2/SSO, …) go through `SaTokenConfig.serializer` (`SharedSerializer`). Default is JSON. Optional binary encoding needs Cargo feature `fory` and `.serializer(SharedSerializer::from(ForySerializer::default()))`. Fory can still **read** legacy pure JSON (rolling upgrade); switching writers back to JSON while binary rows remain will fail with a format mismatch. Full guide: [Storage](./storage.md).

## Removed items and replacements

| Removed / deprecated | Replacement |
|----------------------|-------------|
| `SaStorage::keys` | `SaStorage::scan` until `next_cursor == 0` |
| Direct `SaStorage` in services | `SaTokenDao` (`set_object` / `get_object` / `cas` / `list_*`) |
| `sa-token-plugin-*-core` | `sa-token-plugin-common` (`SaTokenState`) |
| `FrameworkAdapter` | `sa_token_adapter::plugin::SaTokenPlugin` |
| `init_manager` as happy path | `try_init_manager` → `Result` |
| `put_stp_logic` / global registry | **Deprecated no-ops** — use `SaLogic::new` / `StpUtil::stp_logic` (cheap Clone façade; no registry) |
| Process-local OAuth2/SSO `HashMap` | Dao-backed stores |

```rust
// 0.1.x
// use sa_token_plugin_axum_core::SaTokenState;

// 0.2.0
use sa_token_plugin_common::SaTokenState;
// or: use sa_token_plugin_axum::*;
```

## Signatures and modules

Prefer `try_build` / `try_init_manager` / `try_get_manager`. Adapters should read tokens with `token_io::read_token`. Login and grants go through `AuthService` / `AuthzService`. Multi-account uses `login_type` + `SaLogic`. `StpUtil::login` always uses default `login_type`; use `login_with_type` / `TokenBuilder` / `SaLogic` for others.

Real new paths include: `dao.rs`, `keys.rs`, `token_io.rs`, `codec.rs`, `service/`, `stp_logic.rs`, `oauth2/`, `sso/`, `cleanup/`, and `sa-token-plugin-common`. Adapter adds `SaSerializer` / `SharedSerializer`. Dao has **no** `set_json`; configuration errors use `ConfigError`.

## Storage capability (short)

| Capability | Memory | Redis | Database |
|------------|--------|-------|----------|
| Basic KV | yes | yes | yes |
| `get_del` / CAS / list / `scan` | yes | yes | **Unsupported** |

Do not rely on the database backend for nonce one-shot consume, online indexes, or multi-device lists yet.

## Upgrade checklist

1. Bump every `sa-token-*` dependency to `0.2.0`.
2. Replace `*-core` imports with `sa-token-plugin-common` / the plugin prelude.
3. Switch `init_manager` → `try_init_manager`; use `try_build` in libraries.
4. Handle `Result` from token generation, online users, and JWT.
5. Set `auto_renew(true)` only if you need 0.1.x renewal.
6. Move public routes to `PathAuthConfig::exclude`.
7. Configure `token_prefix` / `is_write_cookie` when needed.
8. Re-read OAuth2 (hashed secrets, PKCE) and SSO ticket consume.
9. Replace `put_stp_logic` with `SaLogic::new` / `StpUtil::stp_logic` (registry is gone; old APIs are no-ops).
10. If you need non-JSON storage encoding, enable `fory` and set `.serializer(...)` — see [Storage](/guide/storage.md).
11. Run `cargo check --workspace`, then `cargo clippy --workspace --lib`.

## Related links

- [Quick start](/guide/quick-start.md)
- [Path auth](/guide/path-auth.md)
- [Storage](/guide/storage.md)
- [Error reference](/reference/error-reference.md)
- Issues: https://github.com/sa-tokens/sa-token-rust/issues
