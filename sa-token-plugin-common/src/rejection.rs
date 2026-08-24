// Author: 金书记
//
//! Unified 401 / 403 / 428 JSON rejection bodies.
//!
//! All framework bindings **must** use these helpers to construct error responses.

use sa_token_core::SaTokenError;
use sa_token_core::error::messages;
use serde_json::{Value, json};

/// Framework-agnostic HTTP status codes (mapped to `StatusCode` in each binding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaTokenHttpStatus {
    /// 401 — unauthenticated or invalid token.
    Unauthorized = 401,
    /// 403 — authenticated but insufficient permissions / roles.
    Forbidden = 403,
    /// 428 — safe (secondary) authentication required.
    PreconditionRequired = 428,
    /// 500 — unexpected / storage failure.
    InternalServerError = 500,
}

/// `{"code":401,"message":"Authentication error"}`
pub fn unauthorized_json() -> Value {
    json!({
        "code": SaTokenHttpStatus::Unauthorized as u16,
        "message": messages::AUTH_ERROR,
    })
}

/// `{"code":403,"message":"<reason or Permission required>"}`
pub fn forbidden_json(reason: Option<&str>) -> Value {
    json!({
        "code": SaTokenHttpStatus::Forbidden as u16,
        "message": reason.unwrap_or(messages::PERMISSION_REQUIRED),
    })
}

/// `{"code":403,"message":"Role required"}`
pub fn forbidden_role_json() -> Value {
    json!({
        "code": SaTokenHttpStatus::Forbidden as u16,
        "message": messages::ROLE_REQUIRED,
    })
}

/// `{"code":428,"message":"Safe authentication required for service: <svc>"}`
pub fn safe_required_json(service: &str) -> Value {
    json!({
        "code": SaTokenHttpStatus::PreconditionRequired as u16,
        "message": format!("Safe authentication required for service: {service}"),
    })
}

/// Header name for Basic challenge responses.
pub const WWW_AUTHENTICATE: &str = "WWW-Authenticate";

/// Header value: `Basic realm="<realm>"`
pub fn www_authenticate_basic(realm: &str) -> String {
    format!("Basic realm=\"{realm}\"")
}

/// JSON 401 body + `WWW-Authenticate` value for HTTP Basic failures.
pub fn unauthorized_basic_json(realm: &str) -> (Value, String) {
    (
        json!({
            "code": SaTokenHttpStatus::Unauthorized as u16,
            "message": messages::BASIC_AUTH_FAILED,
        }),
        www_authenticate_basic(realm),
    )
}

/// Map [`SaTokenError`] → (status, JSON body, optional `WWW-Authenticate` value).
/// 将 [`SaTokenError`] 映射为（状态码、JSON 体、可选 `WWW-Authenticate` 值）。
pub fn http_rejection_for(err: &SaTokenError) -> (SaTokenHttpStatus, Value, Option<String>) {
    match err {
        SaTokenError::BasicAuthFailed { realm } => {
            let (body, www) = unauthorized_basic_json(realm);
            (SaTokenHttpStatus::Unauthorized, body, Some(www))
        }
        SaTokenError::NotLogin
        | SaTokenError::TokenExpired
        | SaTokenError::TokenNotFound
        | SaTokenError::TokenInactive
        | SaTokenError::SameTokenInvalid => {
            (SaTokenHttpStatus::Unauthorized, unauthorized_json(), None)
        }
        SaTokenError::RoleDenied(_) => (SaTokenHttpStatus::Forbidden, forbidden_role_json(), None),
        SaTokenError::PermissionDenied
        | SaTokenError::PermissionDeniedDetail(_)
        | SaTokenError::AccountBanned(_)
        | SaTokenError::DisableService { .. }
        | SaTokenError::TerminalDenied { .. } => (
            SaTokenHttpStatus::Forbidden,
            forbidden_json(Some(&err.to_string())),
            None,
        ),
        SaTokenError::NotSafe(service) => (
            SaTokenHttpStatus::PreconditionRequired,
            safe_required_json(service),
            None,
        ),
        _ => (
            SaTokenHttpStatus::InternalServerError,
            json!({"code": 500, "message": "internal error"}),
            None,
        ),
    }
}

/// JSON `Content-Type` header value.
pub const CONTENT_TYPE_JSON: &str = "application/json; charset=utf-8";

/// Serialize a JSON `Value` to UTF-8 bytes for writing into a response body.
pub fn write_json_body(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value)
        .unwrap_or_else(|_| br#"{"code":500,"message":"Internal error"}"#.to_vec())
}
