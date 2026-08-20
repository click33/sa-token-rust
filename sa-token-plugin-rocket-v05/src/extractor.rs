// Author: 金书记
//
//! Rocket request guards using common rejection helpers.

use rocket::http::ContentType;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::{self, Responder};
use sa_token_core::{SaTokenContext, token::TokenValue};
use sa_token_plugin_common::rejection;
use std::sync::Arc;

/// Authentication error response (401 JSON body).
#[derive(Debug)]
pub struct AuthError {
    json: String,
}

impl<'r> Responder<'r, 'static> for AuthError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let mut response = rocket::Response::new();
        response.set_header(ContentType::JSON);
        response.set_status(Status::Unauthorized);
        response.set_sized_body(self.json.len(), std::io::Cursor::new(self.json));
        Ok(response)
    }
}

/// Token guard — returns 401 when missing.
pub struct SaTokenGuard(pub TokenValue);

impl SaTokenGuard {
    pub fn token(&self) -> &TokenValue {
        &self.0
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SaTokenGuard {
    type Error = AuthError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = request.local_cache(|| None::<TokenValue>);
        if let Some(token) = token {
            return Outcome::Success(SaTokenGuard(token.clone()));
        }

        Outcome::Error((
            Status::Unauthorized,
            AuthError {
                json: rejection::unauthorized_json().to_string(),
            },
        ))
    }
}

/// Optional token guard — never rejects.
pub struct OptionalSaTokenGuard(pub Option<TokenValue>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OptionalSaTokenGuard {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = request.local_cache(|| None::<TokenValue>).clone();
        Outcome::Success(OptionalSaTokenGuard(token))
    }
}

/// Request-scoped [`SaTokenContext`] from Fairing `local_cache` (safe across `.await`).
pub struct SaCtx(pub Arc<SaTokenContext>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SaCtx {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let ctx = req.local_cache(|| Arc::new(SaTokenContext::new()));
        Outcome::Success(SaCtx(ctx.clone()))
    }
}

/// LoginId guard — returns 401 when missing.
pub struct LoginIdGuard(pub String);

impl LoginIdGuard {
    pub fn login_id(&self) -> &str {
        &self.0
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for LoginIdGuard {
    type Error = AuthError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let login_id = request.local_cache(|| None::<String>);
        if let Some(login_id) = login_id {
            return Outcome::Success(LoginIdGuard(login_id.clone()));
        }

        Outcome::Error((
            Status::Unauthorized,
            AuthError {
                json: rejection::unauthorized_json().to_string(),
            },
        ))
    }
}
