// Author: 金书记
//
// 中文 | English
// Tide 认证中间件 | Tide authentication middleware

use crate::layer::TideRequestAdapter;
use async_trait::async_trait;
use sa_token_core::StpUtil;
use sa_token_core::router::run_auth_flow;
use sa_token_plugin_common::{SaLoginId, SaTokenState, rejection};
use tide_017::{Middleware, Next, Request, Response, StatusCode};

/// 中文 | English
/// 认证中间件 - 验证用户登录状态 | Authentication middleware - verify user login status
///
/// # 示例 | Example
/// ```rust,ignore
/// use tide_017::prelude::*;
/// use sa_token_plugin_tide::AuthMiddleware;
///
/// let mut app = tide_017::new();
/// app.with(AuthMiddleware);
/// app.at("/user").get(user_handler);
/// ```
#[derive(Clone)]
pub struct AuthMiddleware;

#[async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for AuthMiddleware {
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> tide_017::Result {
        // 中文 | English
        // 从请求头中获取 token | Get token from request headers
        let token = req
            .header("Authorization")
            .and_then(|v| v.as_str().strip_prefix("Bearer "))
            .map(|s| s.to_string());

        if let Some(token_str) = token {
            // 中文 | English
            // 验证 token 是否有效 | Verify if token is valid
            use sa_token_core::TokenValue;
            let token_value = TokenValue::from(token_str.clone());
            if StpUtil::is_login(&token_value).await {
                // 中文 | English
                // Token 有效，将 login_id 存入扩展数据 | Token valid, store login_id in extensions
                if let Ok(login_id) = StpUtil::get_login_id(&token_value).await {
                    req.set_ext(SaLoginId(login_id));
                    return Ok(next.run(req).await);
                }
            }
        }

        let mut res = Response::new(StatusCode::Unauthorized);
        res.set_body(rejection::unauthorized_json().to_string());
        res.set_content_type("application/json");
        Ok(res)
    }
}

/// 中文 | English
/// 权限验证中间件 - 验证用户是否拥有指定权限 | Permission middleware - verify if user has specified permissions
///
/// # 示例 | Example
/// ```rust,ignore
/// let mut app = tide_017::new();
/// app.with(PermissionMiddleware::new("user:read"));
/// ```
#[derive(Clone)]
pub struct PermissionMiddleware {
    permission: String,
}

impl PermissionMiddleware {
    /// 中文 | English
    /// 创建权限验证中间件 | Create permission middleware
    pub fn new(permission: impl Into<String>) -> Self {
        Self {
            permission: permission.into(),
        }
    }
}

#[async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for PermissionMiddleware {
    async fn handle(&self, req: Request<State>, next: Next<'_, State>) -> tide_017::Result {
        // 中文 | English
        // 从扩展数据获取 login_id | Get login_id from extensions
        if let Some(login_id) = req.ext::<SaLoginId>() {
            // 中文 | English
            // 验证权限 | Verify permission
            if StpUtil::has_permission(login_id.as_str(), &self.permission).await {
                return Ok(next.run(req).await);
            }
        }

        let mut res = Response::new(StatusCode::Forbidden);
        res.set_body(rejection::forbidden_json(None).to_string());
        res.set_content_type("application/json");
        Ok(res)
    }
}

/// 中文 | English
/// Sa-Token 登录检查中间件 | Sa-Token login check middleware
///
/// 使用标准错误消息，检查当前请求是否已登录 | Uses standard error messages, checks if current request is logged in
#[derive(Clone)]
pub struct SaCheckLoginMiddleware {
    pub state: SaTokenState,
}

impl SaCheckLoginMiddleware {
    /// 中文 | English
    /// 创建新的登录检查中间件 | Create new login check middleware
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for SaCheckLoginMiddleware {
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> tide_017::Result {
        let adapter = TideRequestAdapter::new(&req);
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        if flow.token.is_none() || flow.login_id.is_none() {
            let mut res = Response::new(StatusCode::Unauthorized);
            res.set_body(rejection::unauthorized_json().to_string());
            res.set_content_type("application/json");
            return Ok(res);
        }

        if let Some(t) = &flow.token {
            req.set_ext(t.clone());
        }
        if let Some(id) = &flow.login_id {
            req.set_ext(SaLoginId(id.clone()));
        }

        Ok(flow.run(next.run(req)).await)
    }
}

/// 中文 | English
/// Sa-Token 权限检查中间件 | Sa-Token permission check middleware
///
/// 检查当前请求用户是否拥有指定权限 | Checks if current request user has specified permission
#[derive(Clone)]
pub struct SaCheckPermissionMiddleware {
    pub state: SaTokenState,
    permission: String,
}

impl SaCheckPermissionMiddleware {
    /// 中文 | English
    /// 创建新的权限检查中间件 | Create new permission check middleware
    pub fn new(state: SaTokenState, permission: impl Into<String>) -> Self {
        Self {
            state,
            permission: permission.into(),
        }
    }
}

#[async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for SaCheckPermissionMiddleware {
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> tide_017::Result {
        let adapter = TideRequestAdapter::new(&req);
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        let Some(login_id) = flow.login_id.clone() else {
            let mut res = Response::new(StatusCode::Forbidden);
            res.set_body(rejection::forbidden_json(None).to_string());
            res.set_content_type("application/json");
            return Ok(res);
        };

        if !StpUtil::has_permission(&login_id, &self.permission).await {
            let mut res = Response::new(StatusCode::Forbidden);
            res.set_body(rejection::forbidden_json(None).to_string());
            res.set_content_type("application/json");
            return Ok(res);
        }

        if let Some(t) = &flow.token {
            req.set_ext(t.clone());
        }
        req.set_ext(SaLoginId(login_id));

        Ok(flow.run(next.run(req)).await)
    }
}

/// 中文 | English
/// Sa-Token 角色检查中间件 | Sa-Token role check middleware
///
/// 检查当前请求用户是否拥有指定角色 | Checks if current request user has specified role
#[derive(Clone)]
pub struct SaCheckRoleMiddleware {
    pub state: SaTokenState,
    role: String,
}

impl SaCheckRoleMiddleware {
    /// 中文 | English
    /// 创建新的角色检查中间件 | Create new role check middleware
    pub fn new(state: SaTokenState, role: impl Into<String>) -> Self {
        Self {
            state,
            role: role.into(),
        }
    }
}

#[async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for SaCheckRoleMiddleware {
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> tide_017::Result {
        let adapter = TideRequestAdapter::new(&req);
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        let Some(login_id) = flow.login_id.clone() else {
            let mut res = Response::new(StatusCode::Forbidden);
            res.set_body(rejection::forbidden_role_json().to_string());
            res.set_content_type("application/json");
            return Ok(res);
        };

        if !StpUtil::has_role(&login_id, &self.role).await {
            let mut res = Response::new(StatusCode::Forbidden);
            res.set_body(rejection::forbidden_role_json().to_string());
            res.set_content_type("application/json");
            return Ok(res);
        }

        if let Some(t) = &flow.token {
            req.set_ext(t.clone());
        }
        req.set_ext(SaLoginId(login_id));

        Ok(flow.run(next.run(req)).await)
    }
}
