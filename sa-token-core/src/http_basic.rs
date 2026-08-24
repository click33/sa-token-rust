// Author: 金书记 | Author: Jin Shuji
//
//! HTTP Basic credential check against the current request's `Authorization` header.
//! 基于当前请求 `Authorization` 头的 HTTP Basic 凭据校验。

use crate::context::SaTokenContext;
use crate::error::{SaTokenError, SaTokenResult};
use crate::util::StpUtil;

/// Default realm string used in `WWW-Authenticate`.
/// `WWW-Authenticate` 使用的默认 realm。
pub const DEFAULT_REALM: &str = "sa-token";

/// Constant-time equality for equal-length byte slices.
/// 等长字节的恒定时间比较（长度不同时直接 false，长度会泄漏，可接受）。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Decode `Authorization: Basic <base64(user:pass)>` into `user:pass`.
/// 将 `Authorization: Basic <base64(user:pass)>` 解码为 `user:pass`。
pub fn decode_basic_authorization(header: &str) -> Option<String> {
    let rest = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let rest = rest.trim();
    if rest.is_empty() {
        return None;
    }
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(rest.as_bytes())
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// Check HTTP Basic.
///
/// `account` format: `user:password`. Empty `account` falls back to `config.http_basic`.
/// `account` 格式为 `user:password`；空则回退 `config.http_basic`。
pub fn check(realm: &str, account: &str) -> SaTokenResult<()> {
    let expected = if account.is_empty() {
        StpUtil::try_get_config()
            .map(|c| c.http_basic.clone())
            .unwrap_or_default()
    } else {
        account.to_string()
    };
    if expected.is_empty() {
        return Err(SaTokenError::BasicAuthFailed {
            realm: realm.to_string(),
        });
    }

    let header = SaTokenContext::try_current()
        .and_then(|ctx| ctx.auth_meta().authorization)
        .ok_or_else(|| SaTokenError::BasicAuthFailed {
            realm: realm.to_string(),
        })?;

    let decoded =
        decode_basic_authorization(&header).ok_or_else(|| SaTokenError::BasicAuthFailed {
            realm: realm.to_string(),
        })?;

    if !ct_eq(decoded.as_bytes(), expected.as_bytes()) {
        return Err(SaTokenError::BasicAuthFailed {
            realm: realm.to_string(),
        });
    }
    Ok(())
}

/// Check using default realm and config / explicit account.
/// 使用默认 realm，以及配置或显式账号进行校验。
pub fn check_account(account: &str) -> SaTokenResult<()> {
    check(DEFAULT_REALM, account)
}
