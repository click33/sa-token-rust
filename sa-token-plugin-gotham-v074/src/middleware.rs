// Author: 金书记
//
//! 中间件实现
//!
//! 提供多种中间件：
//! - `SaTokenMiddleware`：基础 token 提取和验证中间件
//! - `SaCheckLoginMiddleware`：检查登录中间件，未登录时返回401错误
//! - `SaCheckPermissionMiddleware`：检查权限中间件，无权限时返回403错误
//! - `SaCheckRoleMiddleware`：检查角色中间件，无角色时返回403错误
//! - `AuthMiddleware`：已废弃，建议使用上述中间件

use gotham::handler::HandlerFuture;
use gotham::hyper::body::Body;
use gotham::hyper::{Response, StatusCode};
use gotham::middleware::Middleware;
use gotham::state::{State, StateData};
use sa_token_core::{StpUtil, router::run_auth_flow};
use sa_token_plugin_common::{SaTokenState, rejection};
use std::pin::Pin;

use crate::adapter::GothamCapturedRequest;
use crate::wrapper::{LoginIdWrapper, TokenValueWrapper};

/// 中文 | English
/// 登录 ID 状态数据 | Login ID state data
#[derive(Clone, StateData)]
pub struct LoginId(pub String);

/// sa-token 基础中间件 - 提取并验证 token
///
/// 此中间件会从请求中提取 token，验证其有效性，并将相关信息存储到 State 中
#[derive(Clone)]
pub struct SaTokenMiddleware {
    pub state: SaTokenState,
}

impl SaTokenMiddleware {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

impl Middleware for SaTokenMiddleware {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Pin<Box<HandlerFuture>>
    where
        Chain: FnOnce(State) -> Pin<Box<HandlerFuture>> + Send + 'static,
    {
        let token_state = self.state.clone();

        Box::pin(async move {
            let token_name = token_state.manager.config.token_name.as_str();
            let adapter = GothamCapturedRequest::capture(&state, token_name);
            let flow = run_auth_flow(&adapter, &token_state.manager, None).await;

            if let Some(ref t) = flow.token {
                state.put(TokenValueWrapper(t.clone()));
            }
            if let Some(ref id) = flow.login_id {
                state.put(LoginIdWrapper(id.clone()));
            }

            flow.run(chain(state)).await
        })
    }
}

/// 中文 | English
/// 认证中间件 - 验证用户登录状态 | Authentication middleware - verify user login status
///
/// 注意：此中间件已废弃，建议使用 SaTokenMiddleware + SaCheckLoginMiddleware
#[deprecated(note = "Use SaTokenMiddleware + SaCheckLoginMiddleware instead")]
#[derive(Clone)]
pub struct AuthMiddleware;

#[allow(deprecated)]
impl AuthMiddleware {
    /// 中文 | English
    /// 创建新的认证中间件 | Create a new authentication middleware
    pub fn new() -> Self {
        Self
    }
}

#[allow(deprecated)]
impl Middleware for AuthMiddleware {
    fn call<Chain>(self, state: State, chain: Chain) -> Pin<Box<HandlerFuture>>
    where
        Chain: FnOnce(State) -> Pin<Box<HandlerFuture>> + Send + 'static,
    {
        // 注意：Gotham 的 State 系统较为复杂
        // 这里提供一个简化实现，用户可以根据需要扩展
        // 建议在 handler 中手动验证 token
        Box::pin(chain(state))
    }
}

#[allow(deprecated)]
impl Default for AuthMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

/// sa-token 登录检查中间件 - 强制要求登录
///
/// 此中间件会检查用户是否已登录，如果未登录则返回401错误
/// 建议与 SaTokenMiddleware 一起使用
#[derive(Clone)]
pub struct SaCheckLoginMiddleware {
    pub state: SaTokenState,
}

impl SaCheckLoginMiddleware {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

impl Middleware for SaCheckLoginMiddleware {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Pin<Box<HandlerFuture>>
    where
        Chain: FnOnce(State) -> Pin<Box<HandlerFuture>> + Send + 'static,
    {
        let token_state = self.state.clone();

        Box::pin(async move {
            let token_name = token_state.manager.config.token_name.as_str();
            let adapter = GothamCapturedRequest::capture(&state, token_name);
            let flow = run_auth_flow(&adapter, &token_state.manager, None).await;

            if flow.token.is_none() || flow.login_id.is_none() {
                let response = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("Content-Type", rejection::CONTENT_TYPE_JSON)
                    .body(Body::from(rejection::unauthorized_json().to_string()))
                    .unwrap_or_else(|_| Response::new(Body::empty()));

                return Ok((state, response));
            }

            if let Some(ref t) = flow.token {
                state.put(TokenValueWrapper(t.clone()));
            }
            if let Some(ref id) = flow.login_id {
                state.put(LoginIdWrapper(id.clone()));
            }

            flow.run(chain(state)).await
        })
    }
}

/// sa-token 权限检查中间件 - 强制要求特定权限
///
/// 此中间件会检查用户是否拥有指定权限，如果没有则返回403错误
#[derive(Clone)]
pub struct SaCheckPermissionMiddleware {
    pub state: SaTokenState,
    permission: String,
}

impl SaCheckPermissionMiddleware {
    pub fn new(state: SaTokenState, permission: impl Into<String>) -> Self {
        Self {
            state,
            permission: permission.into(),
        }
    }
}

impl Middleware for SaCheckPermissionMiddleware {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Pin<Box<HandlerFuture>>
    where
        Chain: FnOnce(State) -> Pin<Box<HandlerFuture>> + Send + 'static,
    {
        let token_state = self.state.clone();
        let permission = self.permission.clone();

        Box::pin(async move {
            let token_name = token_state.manager.config.token_name.as_str();
            let adapter = GothamCapturedRequest::capture(&state, token_name);
            let flow = run_auth_flow(&adapter, &token_state.manager, None).await;

            let Some(login_id) = flow.login_id.clone() else {
                let response = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("Content-Type", rejection::CONTENT_TYPE_JSON)
                    .body(Body::from(rejection::unauthorized_json().to_string()))
                    .unwrap_or_else(|_| Response::new(Body::empty()));

                return Ok((state, response));
            };

            if !StpUtil::has_permission(&login_id, &permission).await {
                let response = Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", rejection::CONTENT_TYPE_JSON)
                    .body(Body::from(rejection::forbidden_json(None).to_string()))
                    .unwrap_or_else(|_| Response::new(Body::empty()));

                return Ok((state, response));
            }

            if let Some(ref t) = flow.token {
                state.put(TokenValueWrapper(t.clone()));
            }
            state.put(LoginIdWrapper(login_id));

            flow.run(chain(state)).await
        })
    }
}

/// sa-token 角色检查中间件 - 强制要求特定角色
///
/// 此中间件会检查用户是否拥有指定角色，如果没有则返回403错误
#[derive(Clone)]
pub struct SaCheckRoleMiddleware {
    pub state: SaTokenState,
    role: String,
}

impl SaCheckRoleMiddleware {
    pub fn new(state: SaTokenState, role: impl Into<String>) -> Self {
        Self {
            state,
            role: role.into(),
        }
    }
}

impl Middleware for SaCheckRoleMiddleware {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Pin<Box<HandlerFuture>>
    where
        Chain: FnOnce(State) -> Pin<Box<HandlerFuture>> + Send + 'static,
    {
        let token_state = self.state.clone();
        let role = self.role.clone();

        Box::pin(async move {
            let token_name = token_state.manager.config.token_name.as_str();
            let adapter = GothamCapturedRequest::capture(&state, token_name);
            let flow = run_auth_flow(&adapter, &token_state.manager, None).await;

            let Some(login_id) = flow.login_id.clone() else {
                let response = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("Content-Type", rejection::CONTENT_TYPE_JSON)
                    .body(Body::from(rejection::unauthorized_json().to_string()))
                    .unwrap_or_else(|_| Response::new(Body::empty()));

                return Ok((state, response));
            };

            if !StpUtil::has_role(&login_id, &role).await {
                let response = Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", rejection::CONTENT_TYPE_JSON)
                    .body(Body::from(rejection::forbidden_role_json().to_string()))
                    .unwrap_or_else(|_| Response::new(Body::empty()));

                return Ok((state, response));
            }

            if let Some(ref t) = flow.token {
                state.put(TokenValueWrapper(t.clone()));
            }
            state.put(LoginIdWrapper(login_id));

            flow.run(chain(state)).await
        })
    }
}
