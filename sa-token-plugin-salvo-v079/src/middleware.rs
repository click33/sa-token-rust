// Author: 金书记
//
// 中文 | English
// Salvo 认证中间件 | Salvo authentication middleware

use sa_token_core::{StpUtil, router::run_auth_flow};
use sa_token_plugin_common::{SaTokenState, rejection};
use salvo::prelude::*;

use crate::adapter::SalvoCapturedRequest;

/// 中文 | English
/// 认证中间件 - 验证用户登录状态 | Authentication middleware - verify user login status
///
/// # 示例 | Example
/// ```rust,ignore
/// use salvo::prelude::*;
/// use sa_token_plugin_salvo::auth_middleware;
///
/// let router = Router::new()
///     .hoop(auth_middleware())
///     .push(Router::with_path("user").get(user_handler));
/// ```
pub fn auth_middleware() -> impl Handler {
    auth_middleware_handler
}

#[handler]
async fn auth_middleware_handler(
    req: &mut Request,
    res: &mut Response,
    depot: &mut Depot,
    ctrl: &mut FlowCtrl,
) {
    // 中文 | English
    // 从请求头中获取 token | Get token from request headers
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    if let Some(token_str) = token {
        // 中文 | English
        // 验证 token 是否有效 | Verify if token is valid
        use sa_token_core::TokenValue;
        let token_value = TokenValue::from(token_str.clone());
        if StpUtil::is_login(&token_value).await {
            // 中文 | English
            // Token 有效，将 login_id 存入 depot | Token valid, store login_id in depot
            if let Ok(login_id) = StpUtil::get_login_id(&token_value).await {
                depot.insert("login_id", login_id);
                ctrl.call_next(req, depot, res).await;
                return;
            }
        }
    }

    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Text::Json(rejection::unauthorized_json().to_string()));
    ctrl.skip_rest();
}

/// 中文 | English
/// 权限验证中间件 - 验证用户是否拥有指定权限 | Permission middleware - verify if user has specified permissions
///
/// # 参数 | Parameters
/// - `permission`: 需要的权限 | Required permission
///
/// # 示例 | Example
/// ```rust,ignore
/// let router = Router::new()
///     .hoop(permission_middleware("user:read"))
///     .push(Router::with_path("user").get(user_handler));
/// ```
pub fn permission_middleware(permission: &'static str) -> impl Handler {
    PermissionMiddleware { permission }
}

struct PermissionMiddleware {
    permission: &'static str,
}

#[handler]
impl PermissionMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        res: &mut Response,
        depot: &mut Depot,
        ctrl: &mut FlowCtrl,
    ) {
        // 中文 | English
        // 从 depot 获取 login_id | Get login_id from depot
        if let Ok(login_id) = depot.get::<String>("login_id") {
            // 中文 | English
            // 验证权限 | Verify permission
            if StpUtil::has_permission(login_id, self.permission).await {
                ctrl.call_next(req, depot, res).await;
                return;
            }
        }

        res.status_code(StatusCode::FORBIDDEN);
        res.render(Text::Json(rejection::forbidden_json(None).to_string()));
        ctrl.skip_rest();
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

#[salvo::async_trait]
impl Handler for SaCheckLoginMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let adapter =
            SalvoCapturedRequest::capture(req, self.state.manager.config.token_name.as_str());
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        if flow.token.is_none() || flow.login_id.is_none() {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Text::Json(rejection::unauthorized_json().to_string()));
            ctrl.skip_rest();
            return;
        }

        if let Some(ref t) = flow.token {
            depot.insert("sa_token", t.clone());
        }
        if let Some(ref id) = flow.login_id {
            depot.insert("sa_login_id", id.clone());
        }

        flow.run(ctrl.call_next(req, depot, res)).await;
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

#[salvo::async_trait]
impl Handler for SaCheckPermissionMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let adapter =
            SalvoCapturedRequest::capture(req, self.state.manager.config.token_name.as_str());
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        let Some(login_id) = flow.login_id.clone() else {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Text::Json(rejection::forbidden_json(None).to_string()));
            ctrl.skip_rest();
            return;
        };

        if !StpUtil::has_permission(&login_id, &self.permission).await {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Text::Json(rejection::forbidden_json(None).to_string()));
            ctrl.skip_rest();
            return;
        }

        if let Some(ref t) = flow.token {
            depot.insert("sa_token", t.clone());
        }
        depot.insert("sa_login_id", login_id);

        flow.run(ctrl.call_next(req, depot, res)).await;
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

#[salvo::async_trait]
impl Handler for SaCheckRoleMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let adapter =
            SalvoCapturedRequest::capture(req, self.state.manager.config.token_name.as_str());
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        let Some(login_id) = flow.login_id.clone() else {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Text::Json(rejection::forbidden_role_json().to_string()));
            ctrl.skip_rest();
            return;
        };

        if !StpUtil::has_role(&login_id, &self.role).await {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Text::Json(rejection::forbidden_role_json().to_string()));
            ctrl.skip_rest();
            return;
        }

        if let Some(ref t) = flow.token {
            depot.insert("sa_token", t.clone());
        }
        depot.insert("sa_login_id", login_id);

        flow.run(ctrl.call_next(req, depot, res)).await;
    }
}
