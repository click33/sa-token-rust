# Error Reference

[中文](/zh/reference/error-reference.md) | English

The unified core error type is `SaTokenError` (in `sa-token-core`). User-visible `Display` / `message()` text is **English** (from `#[error(...)]`).

## SaTokenResult

```rust
pub type SaTokenResult<T> = Result<T, SaTokenError>;
```

Most business and library APIs return this alias. Use `err.is_auth_error()` / `err.is_authz_error()` for coarse classification.

Application-level short message constants (not `SaTokenError` variants) live in `sa_token_core::error::messages` (for example `INVALID_CREDENTIALS`).

---

## Groups by domain

Groups below mirror `sa-token-core/src/error.rs`. Each row has a one-line typical trigger.

### Token / login

| Variant | Typical trigger |
|---------|-----------------|
| `TokenNotFound` | Token missing in storage, or already expired and removed |
| `InvalidToken(String)` | Token format or content failed validation |
| `TokenExpired` | Token explicitly judged expired |
| `NotLogin` | Current request context is not logged in |
| `TokenInactive` | Token exists but is inactive (frozen / not enabled) |
| `TokenEmpty` | Empty token string passed in |
| `TokenTooShort` | Token shorter than the configured minimum |
| `LoginIdNotNumber` | login_id required to be numeric but failed to parse |
| `SessionNotFound` | Session missing or already deleted |

### Authorization (permission / role / terminal)

| Variant | Typical trigger |
|---------|-----------------|
| `PermissionDenied` | Permission check failed (no specific code) |
| `PermissionDeniedDetail(String)` | Missing a named permission |
| `RoleDenied(String)` | Missing a named role |
| `TerminalDenied { expected, actual }` | Device/terminal does not match the allowed pattern |

### Account safety

| Variant | Typical trigger |
|---------|-----------------|
| `AccountBanned(String)` | Account banned until the given time |
| `AccountKickedOut` | Session forcibly kicked |
| `AccountReplaced` | Login replaced on another device |
| `NotSafe(String)` | Secondary auth not completed for a service |
| `DisableService { service, level }` | Account disabled for a service at a level |
| `SameTokenInvalid` | Same-Token header missing or mismatched |
| `BasicAuthFailed { realm }` | HTTP Basic credentials missing or wrong |
| `SignInvalid` | Request signature mismatch |
| `SignTimestampExpired` | Signature timestamp missing or outside the window |
| `TempTokenNotFound` | Temp token missing or already deleted |
| `TempTokenExpired` | Temp token past `expire_at` |

### Initialization

| Variant | Typical trigger |
|---------|-----------------|
| `NotInitialized` | Global APIs used before `StpUtil::try_init_manager` (or equivalent) |
| `AlreadyInitialized` | Global Manager initialized twice |

### Storage / config / serialization / internal

| Variant | Typical trigger |
|---------|-----------------|
| `StorageError(String)` | Underlying `SaStorage` operation failed |
| `ConfigError(String)` | Invalid config (missing storage, bad JWT secret, …), often from `try_build` |
| `SerializationError(String)` | Encode/decode failure. Includes `serde_json::Error` and mapped `SerializerError` (`EncodeFailed` / `DecodeFailed` / `FormatMismatch` / `VersionIncompatible` from pluggable `SaSerializer`) |
| `InternalError(String)` | Unexpected internal failure |

### OAuth2

| Variant | Typical trigger |
|---------|-----------------|
| `OAuth2ClientNotFound` | Client not registered |
| `OAuth2InvalidCredentials` | Invalid client_id / secret |
| `OAuth2ClientIdMismatch` | Token/code does not match client_id |
| `OAuth2RedirectUriMismatch` | redirect_uri does not match registration |
| `OAuth2CodeNotFound` | Authorization code missing or expired |
| `OAuth2AccessTokenNotFound` | Access token missing or expired |
| `OAuth2RefreshTokenNotFound` | OAuth2 refresh token missing or expired |
| `OAuth2InvalidRefreshToken` | OAuth2 refresh token payload invalid |
| `OAuth2InvalidScope` | Invalid scope data |
| `OAuth2PkceRequired` | `code_verifier` required but missing |
| `OAuth2PkceMismatch` | PKCE verification failed |
| `OAuth2TokenRevokeFailed(String)` | Revoke failed |
| `OAuth2UnsupportedGrant` | Unsupported grant_type |
| `OAuth2PkceRequiredForPublicClient` | Public client did not use PKCE S256 |

### SSO

| Variant | Typical trigger |
|---------|-----------------|
| `InvalidTicket` | Ticket missing or invalid |
| `TicketExpired` | Ticket expired |
| `ServiceMismatch` | Service URL does not match registration |
| `SsoSessionNotFound` | SSO session missing |
| `SsoSignInvalid` | SSO request signature invalid |

### Nonce / refresh (sa-token refresh tokens)

| Variant | Typical trigger |
|---------|-----------------|
| `NonceAlreadyUsed` | Nonce already consumed (possible replay) |
| `InvalidNonceFormat` | Invalid nonce format |
| `InvalidNonceTimestamp` | Nonce timestamp invalid or expired |
| `RefreshTokenNotFound` | Refresh token missing or expired |
| `RefreshTokenInvalidData` | Refresh token payload invalid |
| `RefreshTokenMissingLoginId` | Refresh token missing login_id |
| `RefreshTokenInvalidExpireTime` | Invalid expire-time format in refresh token |

---

## Matching example

```rust
use sa_token_core::{SaTokenError, SaTokenResult};

fn map_status(err: SaTokenError) -> u16 {
    match err {
        SaTokenError::NotLogin | SaTokenError::TokenNotFound | SaTokenError::TokenExpired => 401,
        e if e.is_authz_error() => 403,
        SaTokenError::NotInitialized | SaTokenError::ConfigError(_) => 500,
        _ => 400,
    }
}
```

## Related

- [Quick start](/guide/quick-start.md)
- [Storage](/guide/storage.md)
- [Security features](/guide/security-features.md)
- [OAuth2](/guide/oauth2.md)
- [SSO](/guide/sso.md)
