# Token styles

English | [中文](/zh/guide/token-styles.md)

`TokenStyle` controls how login tokens are generated. Default is `Uuid`. JWT needs a secret — see the [JWT guide](./jwt.md).

## Configuration

```rust
use sa_token_core::config::{SaTokenConfig, TokenStyle};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_style(TokenStyle::Random64)
    .try_build()?;
```

## TokenStyle enum

| Variant | Meaning |
|---------|---------|
| `Uuid` | Standard UUID (default) |
| `SimpleUuid` | UUID without hyphens |
| `Random32` | 32-char CSPRNG |
| `Random64` | 64-char CSPRNG |
| `Random128` | 128-char CSPRNG |
| `Jwt` | JSON Web Token; **`jwt_secret_key` required** or `try_build` fails |
| `Hash` | SHA256 derived from login_id |
| `Timestamp` | Millisecond timestamp + random suffix |
| `Tik` | Short 8-character token |

```rust
SaTokenConfig::builder()
    .storage(storage)
    .token_style(TokenStyle::Jwt)
    .jwt_secret_key("change-me-to-a-long-secret")
    .try_build()?;
```

Opaque styles (`Random*` / `Tik` / `Timestamp`) fit classic session tokens. Use `Jwt` when you need self-contained claims across services. `Hash` is derived from login_id — watch collisions and predictability under multi-device login.

## Related

- [JWT](./jwt.md)
- [StpUtil](./stp-util.md)
- [Quick start](./quick-start.md)
