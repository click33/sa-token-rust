// Author: 金书记 | Author: Jin Shuji
//
//! Same-Token: shared secret for intra-cluster / gateway-to-service calls.
//! Same-Token：集群内 / 网关到服务 调用使用的共享口令。
//!
//! Current value plus one previous value (grace window) are both accepted.
//! 当前值与上一次值（宽限期）均视为有效。

use std::time::Duration;

use crate::error::{SaTokenError, SaTokenResult};
use crate::util::StpUtil;

/// Default header name.
/// 默认请求头名。
pub const DEFAULT_HEADER: &str = "SA-SAME-TOKEN";

fn ttl(timeout_secs: i64) -> Option<Duration> {
    if timeout_secs > 0 {
        Some(Duration::from_secs(timeout_secs as u64))
    } else {
        None
    }
}

fn generate_token() -> SaTokenResult<String> {
    crate::token::random_hex(32)
}

/// Read current Same-Token without creating one.
/// 读取当前 Same-Token（不自动创建）。
pub async fn get_token_nh() -> SaTokenResult<Option<String>> {
    let manager = StpUtil::try_get_manager()?;
    let key = manager.keys().same_token();
    manager.dao().get_string(&key).await
}

/// Read past Same-Token (grace window).
/// 读取宽限期内的上一次 Same-Token。
pub async fn get_past_token_nh() -> SaTokenResult<Option<String>> {
    let manager = StpUtil::try_get_manager()?;
    let key = manager.keys().same_token_past();
    manager.dao().get_string(&key).await
}

/// Get current token, creating one if missing.
/// 获取当前 token，不存在则创建。
pub async fn get_token() -> SaTokenResult<String> {
    if let Some(existing) = get_token_nh().await?
        && !existing.is_empty()
    {
        return Ok(existing);
    }
    refresh_token().await
}

/// Whether `token` equals current or past value (constant-time on equal length).
/// `token` 是否等于当前或宽限值（等长时恒定时间比较）。
pub async fn is_valid(token: &str) -> SaTokenResult<bool> {
    if token.is_empty() {
        return Ok(false);
    }
    let current = get_token_nh().await?;
    if current
        .as_deref()
        .is_some_and(|c| crate::http_basic::ct_eq(c.as_bytes(), token.as_bytes()))
    {
        return Ok(true);
    }
    let past = get_past_token_nh().await?;
    Ok(past
        .as_deref()
        .is_some_and(|p| crate::http_basic::ct_eq(p.as_bytes(), token.as_bytes())))
}

/// Refresh: move current → past, CAS-write a new current.
/// 刷新：当前值写入 past，再用 CAS 写入新的当前值。
pub async fn refresh_token() -> SaTokenResult<String> {
    let manager = StpUtil::try_get_manager()?;
    let timeout = manager.config.same_token_timeout;
    let ttl_opt = ttl(timeout);
    let dao = manager.dao();
    let cur_key = manager.keys().same_token();
    let past_key = manager.keys().same_token_past();

    let current = dao.get_string(&cur_key).await?;
    if let Some(ref cur) = current {
        if !cur.is_empty() {
            dao.set_string(&past_key, cur, ttl_opt).await?;
        }
    }

    let next = generate_token()?;
    let expected = current.as_deref().filter(|s| !s.is_empty());
    let won = dao.cas(&cur_key, expected, &next, ttl_opt).await?;
    if won {
        return Ok(next);
    }
    // Another instance won; return whatever is stored so callers do not split the cluster secret.
    // 另一实例已写入；返回存储中的值，避免集群共享口令分叉。
    dao.get_string(&cur_key)
        .await?
        .filter(|s| !s.is_empty())
        .ok_or(SaTokenError::SameTokenInvalid)
}

/// Check a raw token string.
/// 校验原始 token 字符串。
pub async fn check_token(token: &str) -> SaTokenResult<()> {
    if is_valid(token).await? {
        Ok(())
    } else {
        Err(SaTokenError::SameTokenInvalid)
    }
}

/// Check the Same-Token captured on the current request.
/// 校验当前请求上下文中捕获的 Same-Token。
pub async fn check_current_request() -> SaTokenResult<()> {
    let value = crate::context::SaTokenContext::try_current()
        .and_then(|ctx| ctx.auth_meta().same_token)
        .unwrap_or_default();
    check_token(&value).await
}
