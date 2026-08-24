// Author: 金书记
//
//! Actix-web extractors using common rejection helpers.

use actix_web::{FromRequest, HttpMessage, HttpRequest, dev::Payload, error::ErrorUnauthorized};
use sa_token_core::token::TokenValue;
use sa_token_plugin_common::{SaLoginId, rejection};
use std::future::{Ready, ready};

/// Token extractor (required) — returns 401 when missing.
pub struct SaTokenExtractor(pub TokenValue);

impl FromRequest for SaTokenExtractor {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match req.extensions().get::<TokenValue>() {
            Some(token) => ready(Ok(SaTokenExtractor(token.clone()))),
            None => ready(Err(ErrorUnauthorized(
                rejection::unauthorized_json().to_string(),
            ))),
        }
    }
}

/// Optional token extractor — never rejects.
pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl FromRequest for OptionalSaTokenExtractor {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = req.extensions().get::<TokenValue>().cloned();
        ready(Ok(OptionalSaTokenExtractor(token)))
    }
}

/// LoginId extractor — returns 401 when missing.
pub struct LoginIdExtractor(pub String);

impl FromRequest for LoginIdExtractor {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match req.extensions().get::<SaLoginId>() {
            Some(login_id) => ready(Ok(LoginIdExtractor(login_id.0.clone()))),
            None => ready(Err(ErrorUnauthorized(
                rejection::unauthorized_json().to_string(),
            ))),
        }
    }
}
