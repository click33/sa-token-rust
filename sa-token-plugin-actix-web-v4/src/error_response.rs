// Author: 金书记 | Author: Jin Shuji
//! Map `SaTokenError` to Actix-web responses (incl. Basic `WWW-Authenticate`).
//! 将 `SaTokenError` 映射为 Actix-web 响应（含 Basic 的 `WWW-Authenticate`）。

use actix_web::HttpResponse;
use sa_token_core::SaTokenError;
use sa_token_plugin_common::{CONTENT_TYPE_JSON, WWW_AUTHENTICATE, http_rejection_for};

/// Build an Actix [`HttpResponse`] for a [`SaTokenError`].
/// 为 [`SaTokenError`] 构建 Actix [`HttpResponse`]。
pub fn sa_token_error_response(err: &SaTokenError) -> HttpResponse {
    let (st, body, www) = http_rejection_for(err);
    let mut builder = HttpResponse::build(
        actix_web::http::StatusCode::from_u16(st as u16)
            .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR),
    );
    builder.insert_header((actix_web::http::header::CONTENT_TYPE, CONTENT_TYPE_JSON));
    if let Some(v) = www {
        builder.insert_header((WWW_AUTHENTICATE, v));
    }
    builder.body(body.to_string())
}
