// Author: 金书记
//
//! Type-safe extension / depot keys for writing auth-flow results into
//! framework-specific request storage, avoiding collisions with business-layer
//! arbitrary `String` inserts.

use sa_token_core::router::AuthFlowResult;
use sa_token_core::token::TokenValue;

/// Newtype wrapper for `login_id` stored in extensions (avoids clashing with
/// arbitrary `String` values that business code might insert).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SaLoginId(pub String);

impl SaLoginId {
    /// Borrow as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<String> for SaLoginId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for SaLoginId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Write auth-flow results into typed `http::Extensions` (Axum / Actix / Poem).
///
/// Inserts:
/// - [`TokenValue`] (if present)
/// - [`SaLoginId`] (if present)
/// - [`SaTokenContext`](sa_token_core::SaTokenContext) clone
pub fn apply_to_typed_extensions(extensions: &mut http::Extensions, flow: &AuthFlowResult) {
    if let Some(token) = &flow.token {
        extensions.insert(token.clone());
    }
    if let Some(login_id) = &flow.login_id {
        extensions.insert(SaLoginId(login_id.clone()));
    }
    extensions.insert(flow.context.clone());
}

/// Write auth-flow results using framework-specific insert callbacks
/// (Salvo Depot, Tide `set_ext`, etc.).
pub fn apply_with_callbacks(
    flow: &AuthFlowResult,
    insert_token: impl FnOnce(TokenValue),
    insert_login_id: impl FnOnce(SaLoginId),
    insert_context: impl FnOnce(sa_token_core::SaTokenContext),
) {
    if let Some(token) = &flow.token {
        insert_token(token.clone());
    }
    if let Some(login_id) = &flow.login_id {
        insert_login_id(SaLoginId(login_id.clone()));
    }
    insert_context(flow.context.clone());
}
