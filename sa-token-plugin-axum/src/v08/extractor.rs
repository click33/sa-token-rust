// Author: 金书记
//
//! Axum 0.8 extractors using common rejection helpers.

use axum::{
    Json,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use axum_08 as axum;
use sa_token_core::token::TokenValue;
use sa_token_plugin_common::{SaLoginId, unauthorized_json};

pub struct SaTokenExtractor(pub TokenValue);

impl<S: Send + Sync> FromRequestParts<S> for SaTokenExtractor {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<TokenValue>() {
            Some(token) => Ok(SaTokenExtractor(token.clone())),
            None => Err((StatusCode::UNAUTHORIZED, Json(unauthorized_json())).into_response()),
        }
    }
}

pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl<S: Send + Sync> FromRequestParts<S> for OptionalSaTokenExtractor {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = parts.extensions.get::<TokenValue>().cloned();
        Ok(OptionalSaTokenExtractor(token))
    }
}

pub struct LoginIdExtractor(pub String);

impl<S: Send + Sync> FromRequestParts<S> for LoginIdExtractor {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<SaLoginId>() {
            Some(id) => Ok(LoginIdExtractor(id.0.clone())),
            None => Err((StatusCode::UNAUTHORIZED, Json(unauthorized_json())).into_response()),
        }
    }
}
