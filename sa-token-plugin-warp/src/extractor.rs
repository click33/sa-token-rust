// Author: 金书记
//
// Warp extractors using common rejection helpers.

use sa_token_core::token::TokenValue;
use sa_token_plugin_common::rejection::{forbidden_json, forbidden_role_json, unauthorized_json};
use warp_03::reject::Reject;

/// Authentication error (401).
#[derive(Debug)]
pub struct AuthError;

impl AuthError {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AuthError {
    fn default() -> Self {
        Self::new()
    }
}

impl Reject for AuthError {}

/// Permission error (403).
#[derive(Debug)]
pub struct PermissionError;

impl PermissionError {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PermissionError {
    fn default() -> Self {
        Self::new()
    }
}

impl Reject for PermissionError {}

/// Role error (403).
#[derive(Debug)]
pub struct RoleError;

impl RoleError {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RoleError {
    fn default() -> Self {
        Self::new()
    }
}

impl Reject for RoleError {}

/// Token extractor (required).
pub struct SaTokenExtractor(pub TokenValue);

impl SaTokenExtractor {
    pub fn token(&self) -> &TokenValue {
        &self.0
    }
}

/// Optional token extractor.
pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl OptionalSaTokenExtractor {
    pub fn token(&self) -> Option<&TokenValue> {
        self.0.as_ref()
    }
}

/// LoginId extractor.
pub struct LoginIdExtractor(pub String);

impl LoginIdExtractor {
    pub fn login_id(&self) -> &str {
        &self.0
    }
}

/// Unified rejection handler using common JSON helpers.
pub async fn handle_rejection(
    err: warp_03::Rejection,
) -> Result<impl warp_03::Reply, std::convert::Infallible> {
    let (code, body) = if err.is_not_found() {
        (
            404,
            serde_json::json!({"code": 404, "message": "Not Found"}),
        )
    } else if err.find::<AuthError>().is_some() {
        (401, unauthorized_json())
    } else if err.find::<PermissionError>().is_some() {
        (403, forbidden_json(None))
    } else if err.find::<RoleError>().is_some() {
        (403, forbidden_role_json())
    } else {
        (
            500,
            serde_json::json!({"code": 500, "message": "Internal Server Error"}),
        )
    };

    Ok(warp_03::reply::with_status(
        warp_03::reply::json(&body),
        warp_03::http::StatusCode::from_u16(code)
            .unwrap_or(warp_03::http::StatusCode::INTERNAL_SERVER_ERROR),
    ))
}
