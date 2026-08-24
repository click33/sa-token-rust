# JWT

English | [中文](/zh/guide/jwt.md)

Issue login tokens as JWTs by setting `TokenStyle::Jwt` and `jwt_secret_key`. `try_build` validates this at startup. For standalone sign/verify outside the login pipeline, use `JwtManager`.

## When to use

- Downstream services should verify locally with fewer storage lookups.
- You want `login_id`, expiry, and custom claims inside the token.
- You still use sa-token login/logout, but the token shape is JWT.

## Config and try_build

With `TokenStyle::Jwt` you **must** set a non-empty `jwt_secret_key`, or `try_build` / `try_build_config` fails.

`jwt_fallback_on_error` defaults to **`false`**: JWT generation errors surface immediately instead of silently falling back to a UUID. Enable only if you explicitly accept that degradation.

```rust
use sa_token_core::{SaTokenConfig, TokenStyle};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_style(TokenStyle::Jwt)
    .jwt_secret_key("change-me-to-a-long-secret")
    .jwt_algorithm("HS256") // optional
    .jwt_issuer("my-app")   // optional
    .jwt_audience("api")    // optional
    // .jwt_fallback_on_error(true) // default false; avoid enabling casually
    .try_build()?;
```

Plugin equivalent:

```rust
use sa_token_plugin_axum::*;

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_style(TokenStyle::Jwt)
    .jwt_secret_key("change-me-to-a-long-secret")
    .build();
```

After login the token string is a JWT. Validation still goes through `StpUtil` / Manager token-info reads (signature check plus storage contracts).

## JwtManager (standalone)

For encode/decode without the login pipeline:

```rust
use sa_token_core::{JwtClaims, JwtManager};

let jwt = JwtManager::new("change-me-to-a-long-secret")
    .set_issuer("my-app")
    .set_audience("api");

let mut claims = JwtClaims::new("user_10086");
claims.set_expiration(3600);
claims.set_login_type("user");
claims.add_claim("role", serde_json::json!("admin"));

let token = jwt.generate(&claims)?;
let decoded = jwt.validate(&token)?;
assert_eq!(decoded.login_id, "user_10086");
```

Common APIs: `generate`, `validate`, `refresh`, `extract_login_id`. See `JwtAlgorithm` (default HS256).

## Pitfalls

| Topic | Note |
|-------|------|
| Secret | Use a long random secret in production; do not commit it |
| Fallback | Keep default `false` so failures are visible |
| Storage | JWT style still writes token mappings/indexes; not pure stateless unless you design for that |

## Related

- [Token styles](/guide/token-styles.md)
- [Security features](/guide/security-features.md)
- [Error reference](/reference/error-reference.md)
