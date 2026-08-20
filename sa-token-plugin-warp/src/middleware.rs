// Author: 金书记
//
// Warp middleware convenience filters delegating to layer.rs guards.

use sa_token_plugin_common::SaTokenState;
use warp_03::{Filter, Rejection};

use crate::layer::{sa_check_login, sa_check_permission, sa_check_role};

/// Login-check filter: rejects unauthenticated requests with 401.
pub fn with_auth(state: SaTokenState) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    sa_check_login(state)
}

/// Login-check filter (alias without state — uses global StpUtil, **still
/// needs `sa_token_filter`** earlier in the chain to populate `TokenData`).
pub fn require_auth() -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp_03::any()
        .and(warp_03::filters::ext::get::<crate::filter::TokenData>())
        .and_then(|data: crate::filter::TokenData| async move {
            if data.flow.should_reject() || data.flow.login_id.is_none() {
                Err(warp_03::reject::custom(crate::extractor::AuthError))
            } else {
                Ok(())
            }
        })
        .untuple_one()
}

/// Permission-check filter: requires login + specific permission.
pub fn with_permission(
    state: SaTokenState,
    permission: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    sa_check_permission(state, permission)
}

/// Permission-check filter without state (requires TokenData in extensions).
pub fn require_permission(
    permission: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    let perm = permission.into();
    warp_03::any()
        .and(warp_03::filters::ext::get::<crate::filter::TokenData>())
        .and_then(move |data: crate::filter::TokenData| {
            let p = perm.clone();
            async move {
                let login_id = data
                    .flow
                    .login_id
                    .as_deref()
                    .ok_or_else(|| warp_03::reject::custom(crate::extractor::AuthError))?;
                sa_token_core::StpUtil::check_permission(login_id, &p)
                    .await
                    .map_err(|_| warp_03::reject::custom(crate::extractor::PermissionError))?;
                Ok::<(), Rejection>(())
            }
        })
        .untuple_one()
}

/// Role-check filter: requires login + specific role.
pub fn with_role(
    state: SaTokenState,
    role: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    sa_check_role(state, role)
}

/// Role-check filter without state (requires TokenData in extensions).
pub fn require_role(
    role: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    let r = role.into();
    warp_03::any()
        .and(warp_03::filters::ext::get::<crate::filter::TokenData>())
        .and_then(move |data: crate::filter::TokenData| {
            let r2 = r.clone();
            async move {
                let login_id = data
                    .flow
                    .login_id
                    .as_deref()
                    .ok_or_else(|| warp_03::reject::custom(crate::extractor::AuthError))?;
                sa_token_core::StpUtil::check_role(login_id, &r2)
                    .await
                    .map_err(|_| warp_03::reject::custom(crate::extractor::RoleError))?;
                Ok::<(), Rejection>(())
            }
        })
        .untuple_one()
}
