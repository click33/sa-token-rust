// Author: 金书记
//
//! Poem extractors using common rejection helpers.

use poem_03::http::StatusCode;
use poem_03::{FromRequest, Request, RequestBody, Result};
use sa_token_core::token::TokenValue;
use sa_token_plugin_common::{SaLoginId, rejection};

/// Token + LoginId extractor (required).
#[derive(Clone)]
pub struct SaTokenExtractor {
    token: TokenValue,
    login_id: String,
}

impl SaTokenExtractor {
    pub fn token(&self) -> &TokenValue {
        &self.token
    }

    pub fn login_id(&self) -> &str {
        &self.login_id
    }
}

impl<'a> FromRequest<'a> for SaTokenExtractor {
    async fn from_request(req: &'a Request, _body: &mut RequestBody) -> Result<Self> {
        let token = req
            .extensions()
            .get::<TokenValue>()
            .cloned()
            .ok_or_else(|| {
                poem_03::Error::from_string(
                    rejection::unauthorized_json().to_string(),
                    StatusCode::UNAUTHORIZED,
                )
            })?;

        let login_id = req
            .extensions()
            .get::<SaLoginId>()
            .map(|id| id.0.clone())
            .ok_or_else(|| {
                poem_03::Error::from_string(
                    rejection::unauthorized_json().to_string(),
                    StatusCode::UNAUTHORIZED,
                )
            })?;

        Ok(Self { token, login_id })
    }
}

/// Optional extractor — never rejects.
pub struct OptionalSaTokenExtractor(pub Option<SaTokenExtractor>);

impl<'a> FromRequest<'a> for OptionalSaTokenExtractor {
    async fn from_request(req: &'a Request, _body: &mut RequestBody) -> Result<Self> {
        let token = req.extensions().get::<TokenValue>().cloned();
        let login_id = req.extensions().get::<SaLoginId>().map(|id| id.0.clone());

        match (token, login_id) {
            (Some(token), Some(login_id)) => Ok(Self(Some(SaTokenExtractor { token, login_id }))),
            _ => Ok(Self(None)),
        }
    }
}

/// LoginId extractor (required) — returns 401 when missing.
pub struct LoginIdExtractor(pub String);

impl<'a> FromRequest<'a> for LoginIdExtractor {
    async fn from_request(req: &'a Request, _body: &mut RequestBody) -> Result<Self> {
        let login_id = req
            .extensions()
            .get::<SaLoginId>()
            .map(|id| id.0.clone())
            .ok_or_else(|| {
                poem_03::Error::from_string(
                    rejection::unauthorized_json().to_string(),
                    StatusCode::UNAUTHORIZED,
                )
            })?;

        Ok(Self(login_id))
    }
}
