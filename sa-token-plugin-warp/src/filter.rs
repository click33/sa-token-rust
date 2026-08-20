// Author: 金书记
//
//! Warp Filter: unified through core `run_auth_flow`.

use std::sync::Arc;
use warp_03 as warp;
use warp_03::{Filter, Rejection, http::HeaderMap};

use sa_token_core::router::{AuthFlowResult, PathAuthConfig, run_auth_flow};
use sa_token_core::token::TokenValue;
use sa_token_plugin_common::{SaLoginId, SaTokenState};

use crate::extractor::AuthError;
use crate::snapshot::WarpRequestSnapshot;

/// Request context data (for handler extraction).
#[derive(Clone)]
pub struct TokenData {
    /// Auth flow result (shared across extractors).
    pub flow: Arc<AuthFlowResult>,
}

/// Base filter: extract token, run auth flow, does NOT enforce login.
pub fn sa_token_filter(
    state: SaTokenState,
    path_config: Option<PathAuthConfig>,
) -> impl Filter<Extract = (TokenData,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and(warp::path::full())
        .and(warp::method())
        .and(
            warp::query::<std::collections::HashMap<String, String>>().or_else(|_| async {
                Ok::<(std::collections::HashMap<String, String>,), Rejection>((
                    std::collections::HashMap::new(),
                ))
            }),
        )
        .and(warp::any().map(move || (state.clone(), path_config.clone())))
        .and_then(run_flow)
}

/// Login-enforcing filter: returns 401 rejection when `should_reject`.
pub fn sa_check_login_filter(
    state: SaTokenState,
    path_config: Option<PathAuthConfig>,
) -> impl Filter<Extract = (TokenData,), Error = Rejection> + Clone {
    sa_token_filter(state, path_config).and_then(|data: TokenData| async move {
        if data.flow.should_reject() {
            Err(warp::reject::custom(AuthError))
        } else {
            Ok(data)
        }
    })
}

async fn run_flow(
    headers: HeaderMap,
    path: warp::path::FullPath,
    method: warp::http::Method,
    query: std::collections::HashMap<String, String>,
    (state, path_config): (SaTokenState, Option<PathAuthConfig>),
) -> Result<TokenData, Rejection> {
    let snapshot = WarpRequestSnapshot::capture(headers, query)
        .with_path(path.as_str())
        .with_method(method.as_str());

    let flow = run_auth_flow(&snapshot, &state.manager, path_config.as_ref()).await;

    Ok(TokenData {
        flow: Arc::new(flow),
    })
}

/// Extract `TokenValue` from `TokenData` via extensions.
pub fn extract_token_value() -> impl Filter<Extract = (TokenValue,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::filters::ext::get::<TokenData>())
        .and_then(|data: TokenData| async move {
            match data.flow.token.clone() {
                Some(t) => Ok(t),
                None => Err(warp::reject::custom(AuthError)),
            }
        })
}

/// Extract `SaLoginId` from `TokenData`.
pub fn extract_login_id() -> impl Filter<Extract = (SaLoginId,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::filters::ext::get::<TokenData>())
        .and_then(|data: TokenData| async move {
            match data.flow.login_id.clone() {
                Some(id) => Ok(SaLoginId(id)),
                None => Err(warp::reject::custom(AuthError)),
            }
        })
}

/// Optional `TokenValue` extractor (returns `None` without rejection when missing).
pub fn extract_optional_token_value()
-> impl Filter<Extract = (Option<TokenValue>,), Error = std::convert::Infallible> + Clone {
    warp::any()
        .and(warp::filters::ext::optional::<TokenData>())
        .map(|data: Option<TokenData>| data.and_then(|d| d.flow.token.clone()))
}
