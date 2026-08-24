// Author: 金书记
//
//! Tide extractors using common rejection helpers.

use sa_token_core::token::TokenValue;
use sa_token_plugin_common::{SaLoginId, rejection};
use tide_017::{Request, Response, StatusCode};

/// Authentication error (401).
#[derive(Debug)]
pub struct AuthError;

impl AuthError {
    pub fn new() -> Self {
        Self
    }

    pub fn to_response(&self) -> Response {
        let mut res = Response::new(StatusCode::Unauthorized);
        res.set_body(rejection::unauthorized_json().to_string());
        res.set_content_type("application/json");
        res
    }
}

impl Default for AuthError {
    fn default() -> Self {
        Self::new()
    }
}

/// Token extractor (required).
pub struct SaTokenExtractor(pub TokenValue);

impl SaTokenExtractor {
    pub fn token(&self) -> &TokenValue {
        &self.0
    }

    pub fn from_request<State: Clone + Send + Sync + 'static>(
        req: &Request<State>,
    ) -> Result<Self, AuthError> {
        req.ext::<TokenValue>()
            .cloned()
            .map(SaTokenExtractor)
            .ok_or_else(AuthError::new)
    }
}

/// Optional token extractor — never rejects.
pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl OptionalSaTokenExtractor {
    pub fn token(&self) -> Option<&TokenValue> {
        self.0.as_ref()
    }

    pub fn from_request<State: Clone + Send + Sync + 'static>(req: &Request<State>) -> Self {
        let token = req.ext::<TokenValue>().cloned();
        OptionalSaTokenExtractor(token)
    }
}

/// LoginId extractor (required).
pub struct LoginIdExtractor(pub String);

impl LoginIdExtractor {
    pub fn login_id(&self) -> &str {
        &self.0
    }

    pub fn from_request<State: Clone + Send + Sync + 'static>(
        req: &Request<State>,
    ) -> Result<Self, AuthError> {
        req.ext::<SaLoginId>()
            .map(|id| LoginIdExtractor(id.0.clone()))
            .ok_or_else(AuthError::new)
    }
}
