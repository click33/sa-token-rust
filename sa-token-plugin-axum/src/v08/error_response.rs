// Author: 金书记 | Author: Jin Shuji
//! Map `SaTokenError` to Axum responses (incl. Basic `WWW-Authenticate`).
//! 将 `SaTokenError` 映射为 Axum 响应（含 Basic 的 `WWW-Authenticate`）。

use axum::{
    Json,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use axum_08 as axum;
use sa_token_core::SaTokenError;
use sa_token_plugin_common::{WWW_AUTHENTICATE, http_rejection_for};

/// Build an Axum [`Response`] for a [`SaTokenError`] (sets `WWW-Authenticate` on Basic failures).
/// 为 [`SaTokenError`] 构建 Axum [`Response`]（Basic 失败时设置 `WWW-Authenticate`）。
pub fn sa_token_error_response(err: &SaTokenError) -> Response {
    let (st, body, www) = http_rejection_for(err);
    let status = StatusCode::from_u16(st as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut res = (status, Json(body)).into_response();
    if let Some(v) = www {
        if let Ok(hv) = HeaderValue::from_str(&v) {
            res.headers_mut().insert(WWW_AUTHENTICATE, hv);
        }
    }
    res
}
