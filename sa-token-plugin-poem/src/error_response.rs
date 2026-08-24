// Author: 金书记 | Author: Jin Shuji
//! Map `SaTokenError` to Poem errors/responses (incl. Basic `WWW-Authenticate`).
//! 将 `SaTokenError` 映射为 Poem 错误/响应（含 Basic 的 `WWW-Authenticate`）。

use poem_03::http::{HeaderValue, StatusCode};
use poem_03::{Error, Response};
use sa_token_core::SaTokenError;
use sa_token_plugin_common::{CONTENT_TYPE_JSON, WWW_AUTHENTICATE, http_rejection_for};

/// Build a Poem [`Response`] for a [`SaTokenError`].
/// 为 [`SaTokenError`] 构建 Poem [`Response`]。
pub fn sa_token_error_response(err: &SaTokenError) -> Response {
    let (st, body, www) = http_rejection_for(err);
    let status = StatusCode::from_u16(st as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut res = Response::builder()
        .status(status)
        .header(poem_03::http::header::CONTENT_TYPE, CONTENT_TYPE_JSON)
        .body(body.to_string());
    if let Some(v) = www {
        if let Ok(hv) = HeaderValue::from_str(&v) {
            res.headers_mut().insert(WWW_AUTHENTICATE, hv);
        }
    }
    res
}

/// Build a Poem [`Error`] from [`SaTokenError`] (preserves Basic challenge header when present).
/// 从 [`SaTokenError`] 构建 Poem [`Error`]（Basic 失败时保留挑战头）。
pub fn sa_token_error(err: &SaTokenError) -> Error {
    Error::from_response(sa_token_error_response(err))
}
