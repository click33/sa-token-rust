// Author: 金书记 | Author: Jin Shuji
//! Unified token read/write helpers for HTTP adapters.
//! HTTP 适配器用的统一 token 读写助手。

use sa_token_adapter::context::{CookieOptions, SaRequest, SaResponse, SameSite};
use sa_token_adapter::utils::extract_bearer_or_value;

use crate::config::{SaTokenConfig, TokenCookieConfig};
use crate::token::TokenValue;

/// Read a token using the manager config flags.
/// 按 Manager 配置开关读取 token。
///
/// When `is_read_body` is true, only `get_param` (query / mapped form fields) is
/// read — never consume the HTTP body in middleware.
/// `is_read_body` 为 true 时只读 `get_param`（query / 已映射表单字段），绝不在中间件里消耗 HTTP body。
pub fn read_token<R: SaRequest>(req: &R, config: &SaTokenConfig) -> Option<String> {
    let name = config.token_name.as_str();
    let mut raw: Option<String> = None;

    if config.is_read_header {
        if let Some(v) = req.get_header(name) {
            if !v.trim().is_empty() {
                raw = Some(v);
            }
        }
        if raw.is_none() && !name.eq_ignore_ascii_case("authorization") {
            if let Some(v) = req.get_header("Authorization") {
                if !v.trim().is_empty() {
                    raw = Some(v);
                }
            }
        }
    }

    if raw.is_none() && config.is_read_cookie {
        if let Some(v) = req.get_cookie(name) {
            if !v.trim().is_empty() {
                raw = Some(v);
            }
        }
    }

    // Param/query only — never consume the HTTP body in middleware.
    // 只读 param/query，绝不在中间件里消耗 HTTP body。
    if raw.is_none() && config.is_read_body {
        if let Some(v) = req.get_param(name) {
            if !v.trim().is_empty() {
                raw = Some(v);
            }
        }
    }

    let raw = raw?;
    apply_token_prefix(raw.trim(), config.token_prefix.as_deref())
}

/// Apply prefix rules. `None` keeps historical Bearer stripping.
/// 应用前缀规则。`None` 保持历史上的 Bearer 剥离。
pub fn apply_token_prefix(raw: &str, prefix: Option<&str>) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    match prefix {
        None => {
            let s = extract_bearer_or_value(raw);
            if s.is_empty() { None } else { Some(s) }
        }
        Some(p) => {
            if let Some(rest) = raw.strip_prefix(p) {
                let rest = rest.trim();
                if rest.is_empty() {
                    None
                } else {
                    Some(rest.to_string())
                }
            } else {
                None
            }
        }
    }
}

/// Maps + config, for WebSocket extractors that are not `SaRequest`.
/// 给不是 `SaRequest` 的 WebSocket 提取器使用。
pub fn read_token_from_maps(
    headers: &std::collections::HashMap<String, String>,
    query: &std::collections::HashMap<String, String>,
    config: &SaTokenConfig,
) -> Option<String> {
    let name = config.token_name.as_str();
    let mut raw: Option<String> = None;
    if config.is_read_header {
        if let Some(v) = headers.get(name).filter(|s| !s.trim().is_empty()) {
            raw = Some(v.clone());
        }
        if raw.is_none() && !name.eq_ignore_ascii_case("authorization") {
            if let Some(v) = headers
                .get("Authorization")
                .or_else(|| headers.get("authorization"))
                .filter(|s| !s.trim().is_empty())
            {
                raw = Some(v.clone());
            }
        }
        if raw.is_none() {
            if let Some(v) = headers
                .get("Sec-WebSocket-Protocol")
                .filter(|s| !s.trim().is_empty())
            {
                raw = Some(v.clone());
            }
        }
    }
    if raw.is_none() && config.is_read_body {
        if let Some(v) = query.get(name).filter(|s| !s.trim().is_empty()) {
            raw = Some(v.clone());
        }
        if raw.is_none() {
            if let Some(v) = query.get("token").filter(|s| !s.trim().is_empty()) {
                raw = Some(v.clone());
            }
        }
    }
    apply_token_prefix(raw?.trim(), config.token_prefix.as_deref())
}

/// Write the token cookie when `is_write_cookie` is true.
/// 仅当 `is_write_cookie` 为 true 时写入 token Cookie。
pub fn write_token_cookie<R: SaResponse>(res: &mut R, token: &TokenValue, config: &SaTokenConfig) {
    if !config.cookie.is_write_cookie {
        return;
    }
    let opts = cookie_options(&config.cookie, config.timeout);
    res.set_cookie(config.token_name.as_str(), token.as_str(), opts);
}

/// Clear the token cookie (same guard as write).
/// 清除 token Cookie（与写入同一开关）。
pub fn delete_token_cookie<R: SaResponse>(res: &mut R, config: &SaTokenConfig) {
    if !config.cookie.is_write_cookie {
        return;
    }
    let mut opts = cookie_options(&config.cookie, 0);
    opts.max_age = Some(0);
    res.set_cookie(config.token_name.as_str(), "", opts);
}

fn cookie_options(cookie: &TokenCookieConfig, max_age_secs: i64) -> CookieOptions {
    CookieOptions {
        domain: cookie.domain.clone(),
        path: cookie.path.clone().or_else(|| Some("/".into())),
        max_age: if max_age_secs < 0 {
            None
        } else {
            Some(max_age_secs)
        },
        http_only: cookie.http_only,
        secure: cookie.secure,
        same_site: cookie.same_site.or(Some(SameSite::Lax)),
    }
}
