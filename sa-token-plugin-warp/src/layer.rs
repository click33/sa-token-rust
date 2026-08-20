use std::sync::Arc;

use crate::filter::{self, TokenData};
use sa_token_adapter::context::SaRequest;
use sa_token_adapter::utils::{parse_cookies, parse_query_string};
use sa_token_core::{SaTokenContext, SaTokenError, StpUtil};
use sa_token_plugin_common::SaTokenState;
use warp_03::http::StatusCode;
use warp_03::reply::{self, reply};
use warp_03::{Filter, Rejection, Reply};

/// 中文 | English
/// 创建 Sa-Token 认证层 | Create Sa-Token authentication layer
///
/// 这个过滤器会从请求中提取 token，验证有效性，并设置上下文 | This filter extracts token from request, validates it, and sets context
pub fn sa_token_layer()
-> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    warp_03::any().map(|| {
        SaTokenContext::set_current(SaTokenContext::new());
        reply()
    })
}

/// 中文 | English
/// 清除 Sa-Token 上下文 | Clear Sa-Token context
///
/// 应该在请求处理完成后调用 | Should be called after request handling is done
pub fn sa_token_cleanup()
-> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    warp_03::any().map(|| {
        SaTokenContext::clear();
        reply()
    })
}

/// Bind Sa-Token context to **`tokio::task_local`** (for macros like `#[sa_check_login]`).
/// 将 Sa-Token 上下文绑定到 **`tokio::task_local`**（推荐配合宏 `#[sa_check_login]` 等）。
///
/// Combines `sa_token_filter` + `inner`, installs [`SaTokenContext::scope`] for the inner future.
/// 组合：`sa_token_filter` + `inner`，在内层 future 执行期间安装 [`SaTokenContext::scope`]。
pub fn with_sa_token_scope<F, T>(
    state: SaTokenState,
    inner: F,
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone
where
    F: Filter<Extract = (T,), Error = Rejection> + Clone + Send + Sync + 'static,
    T: Send + 'static,
{
    filter::sa_token_filter(state, None).and(inner).and_then(
        move |token_data: TokenData, value: T| async move {
            let ctx = token_data.flow.context.clone();
            Ok::<_, Rejection>(SaTokenContext::scope(ctx, async move { value }).await)
        },
    )
}

/// warp 过滤器只有 HeaderMap + query，没有完整 Request；用借用视图实现 SaRequest。
/// Warp filters expose HeaderMap + query only; this borrowed view implements SaRequest.
struct WarpParts<'a> {
    headers: &'a warp_03::http::HeaderMap,
    query: &'a str,
}

impl SaRequest for WarpParts<'_> {
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        let raw = self.get_header("cookie")?;
        parse_cookies(&raw).get(name).cloned()
    }

    fn get_param(&self, name: &str) -> Option<String> {
        if self.query.is_empty() {
            return None;
        }
        parse_query_string(self.query).get(name).cloned()
    }

    fn get_path(&self) -> String {
        String::new()
    }

    fn get_method(&self) -> String {
        String::new()
    }
}

/// 中文 | English
/// 从请求中提取 token | Extract token from request
///
/// Respects config `is_read_*` / `token_prefix` via [`token_io::read_token`].
/// 按配置 `is_read_*` / `token_prefix` 通过 [`token_io::read_token`] 读取。
pub fn extract_token_from_request(
    headers: &warp_03::http::HeaderMap,
    query: &str,
    state: &SaTokenState,
) -> Option<String> {
    sa_token_core::token_io::read_token(&WarpParts { headers, query }, &state.manager.config)
}

/// 登录校验过滤器：未登录或 token 无效时 reject。
/// Login guard: rejects unauthenticated requests.
pub fn sa_check_login(state: SaTokenState) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    filter::sa_token_filter(state, None)
        .and_then(|token_data: TokenData| async move {
            match token_data.flow.token {
                Some(ref tv) if token_data.flow.login_id.is_some() => {
                    StpUtil::check_login(tv)
                        .await
                        .map_err(|e| warp_03::reject::custom(SaTokenRejection(e)))?;
                    Ok(())
                }
                _ => Err(warp_03::reject::custom(SaTokenRejection(
                    SaTokenError::NotLogin,
                ))),
            }
        })
        .untuple_one()
}

/// 权限校验过滤器：先确认登录态，再校验权限。
/// Permission guard: verifies the session first, then the permission.
pub fn sa_check_permission(
    state: SaTokenState,
    permission: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    let permission = permission.into();
    filter::sa_token_filter(state, None)
        .and_then(move |token_data: TokenData| {
            let perm = permission.clone();
            async move {
                let login_id = token_data.flow.login_id.clone().ok_or_else(|| {
                    warp_03::reject::custom(SaTokenRejection(SaTokenError::NotLogin))
                })?;

                StpUtil::check_permission(&login_id, &perm)
                    .await
                    .map_err(|e| warp_03::reject::custom(SaTokenRejection(e)))?;
                Ok::<(), Rejection>(())
            }
        })
        .untuple_one()
}

/// 角色校验过滤器 | Role guard
pub fn sa_check_role(
    state: SaTokenState,
    role: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    let role = role.into();
    filter::sa_token_filter(state, None)
        .and_then(move |token_data: TokenData| {
            let role = role.clone();
            async move {
                let login_id = token_data.flow.login_id.clone().ok_or_else(|| {
                    warp_03::reject::custom(SaTokenRejection(SaTokenError::NotLogin))
                })?;

                StpUtil::check_role(&login_id, &role)
                    .await
                    .map_err(|e| warp_03::reject::custom(SaTokenRejection(e)))?;
                Ok::<(), Rejection>(())
            }
        })
        .untuple_one()
}

/// Rejection wrapper for sa-token errors in Warp filters.
/// Warp 过滤器中的 sa-token 错误包装。
#[derive(Debug)]
pub struct SaTokenRejection(pub SaTokenError);

impl warp_03::reject::Reject for SaTokenRejection {}

/// Convert [`SaTokenRejection`] into an HTTP reply (for `.recover`).
/// 将 [`SaTokenRejection`] 转为 HTTP 响应（供 `.recover` 使用）。
pub async fn handle_sa_rejection(err: Rejection) -> Result<impl Reply, std::convert::Infallible> {
    use sa_token_plugin_common::rejection::{
        forbidden_json, forbidden_role_json, unauthorized_json,
    };

    let (status, body) = if let Some(SaTokenRejection(e)) = err.find() {
        match e {
            SaTokenError::NotLogin
            | SaTokenError::TokenExpired
            | SaTokenError::TokenNotFound
            | SaTokenError::TokenInactive => (StatusCode::UNAUTHORIZED, unauthorized_json()),
            SaTokenError::RoleDenied(_) => (StatusCode::FORBIDDEN, forbidden_role_json()),
            SaTokenError::PermissionDenied
            | SaTokenError::PermissionDeniedDetail(_)
            | SaTokenError::AccountBanned(_)
            | SaTokenError::DisableService { .. } => {
                (StatusCode::FORBIDDEN, forbidden_json(Some(&e.to_string())))
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"code": 500, "message": "internal error"}),
            ),
        }
    } else if err.is_not_found() {
        (
            StatusCode::NOT_FOUND,
            serde_json::json!({"code": 404, "message": "not found"}),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"code": 500, "message": "internal error"}),
        )
    };

    Ok(reply::with_status(reply::json(&body), status))
}

/// Keep `Arc` available for callers that re-export this module's types.
#[allow(dead_code)]
fn _keep_arc(_: Arc<()>) {}
