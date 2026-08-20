// Author: 金书记
//
//! Salvo extractors using common rejection helpers.

use sa_token_core::token::TokenValue;
use sa_token_plugin_common::rejection;
use salvo::prelude::*;

/// Authentication error (401).
#[derive(Debug)]
pub struct AuthError;

impl AuthError {
    pub fn new() -> Self {
        Self
    }

    pub fn message(&self) -> &'static str {
        sa_token_core::error::messages::AUTH_ERROR
    }

    pub fn to_json(&self) -> String {
        rejection::unauthorized_json().to_string()
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

    pub fn from_request(req: &Request) -> Result<Self, AuthError> {
        req.extensions()
            .get::<TokenValue>()
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

    pub fn from_request(req: &Request) -> Self {
        let token = req.extensions().get::<TokenValue>().cloned();
        OptionalSaTokenExtractor(token)
    }
}

/// LoginId extractor.
pub struct LoginIdExtractor(pub String);

impl LoginIdExtractor {
    pub fn login_id(&self) -> &str {
        &self.0
    }

    pub fn from_request(req: &Request) -> Result<Self, AuthError> {
        req.extensions()
            .get::<String>()
            .cloned()
            .map(LoginIdExtractor)
            .ok_or_else(AuthError::new)
    }
}
