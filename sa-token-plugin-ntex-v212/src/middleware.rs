// Author: 金书记
//
//! 中间件实现
//!
//! 提供多种中间件：
//! - `SaTokenMiddleware`：基础 token 提取和验证中间件
//! - `SaCheckLoginMiddleware`：检查登录中间件，未登录时返回401错误
//! - `SaCheckPermissionMiddleware`：检查权限中间件，无权限时返回403错误
//! - `SaCheckRoleMiddleware`：检查角色中间件，无角色时返回403错误
//! - `AuthMiddleware`、`PermissionMiddleware`：已废弃，建议使用上述中间件

use ntex::service::{Middleware, Service, ServiceCtx};
use ntex::web::{Error, ErrorRenderer, WebRequest, WebResponse};
use sa_token_core::router::run_auth_flow;
use sa_token_core::{StpUtil, TokenValue, error::messages};
use sa_token_plugin_common::{SaLoginId, SaTokenState};
use serde_json::json;

use crate::adapter::NtexCapturedRequest;
use ntex::web::Error as WebError;
use ntex::web::error::InternalError;

/// sa-token 基础中间件 - 提取并验证 token
///
/// 此中间件会从请求中提取 token，验证其有效性，并将相关信息存储到请求扩展中
pub struct SaTokenMiddleware {
    pub state: SaTokenState,
}

impl SaTokenMiddleware {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

impl<S> Middleware<S> for SaTokenMiddleware {
    type Service = SaTokenMiddlewareService<S>;

    fn create(&self, service: S) -> Self::Service {
        SaTokenMiddlewareService {
            service,
            state: self.state.clone(),
        }
    }
}

pub struct SaTokenMiddlewareService<S> {
    service: S,
    state: SaTokenState,
}

impl<S, Err> Service<WebRequest<Err>> for SaTokenMiddlewareService<S>
where
    S: Service<WebRequest<Err>, Response = WebResponse, Error = Error>,
    Err: ErrorRenderer,
{
    type Response = WebResponse;
    type Error = Error;

    async fn call(
        &self,
        req: WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        let adapter =
            NtexCapturedRequest::capture(&req, self.state.manager.config.token_name.as_str());
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        if let Some(ref t) = flow.token {
            req.extensions_mut().insert(t.clone());
        }
        if let Some(ref id) = flow.login_id {
            req.extensions_mut().insert(SaLoginId(id.clone()));
        }

        flow.run(ctx.call(&self.service, req)).await
    }
}

/// 中文 | English
/// 认证中间件 - 验证用户登录状态 | Authentication middleware - verify user login status
///
/// 注意：此中间件已废弃，建议使用 SaTokenMiddleware + SaCheckLoginMiddleware
///
/// # 示例 | Example
/// ```rust,ignore
/// use ntex::web;
/// use sa_token_plugin_ntex::AuthMiddleware;
///
/// let app = web::App::new()
///     .wrap(AuthMiddleware)
///     .route("/user", web::get().to(user_handler));
/// ```
#[deprecated(note = "Use SaTokenMiddleware + SaCheckLoginMiddleware instead")]
pub struct AuthMiddleware;

#[allow(deprecated)]
impl<S> Middleware<S> for AuthMiddleware {
    type Service = AuthMiddlewareService<S>;

    fn create(&self, service: S) -> Self::Service {
        AuthMiddlewareService { service }
    }
}

pub struct AuthMiddlewareService<S> {
    service: S,
}

impl<S, Err> Service<WebRequest<Err>> for AuthMiddlewareService<S>
where
    S: Service<WebRequest<Err>, Response = WebResponse, Error = Error>,
    Err: ErrorRenderer,
{
    type Response = WebResponse;
    type Error = Error;

    async fn call(
        &self,
        req: WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
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
                // Token 有效，继续处理请求 | Token valid, continue processing
                if let Ok(login_id) = StpUtil::get_login_id(&token_value).await {
                    req.extensions_mut().insert(SaLoginId(login_id));
                    return ctx.call(&self.service, req).await;
                }
            }
        }

        // 中文 | English
        // Token 无效，返回 401 | Token invalid, return 401
        Err(WebError::from(InternalError::new(
            "Unauthorized",
            ntex::http::StatusCode::UNAUTHORIZED,
        )))
    }
}

/// sa-token 登录检查中间件 - 强制要求登录
///
/// 此中间件会检查用户是否已登录，如果未登录则返回401错误
pub struct SaCheckLoginMiddleware {
    pub state: SaTokenState,
}

impl SaCheckLoginMiddleware {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

impl<S> Middleware<S> for SaCheckLoginMiddleware {
    type Service = SaCheckLoginMiddlewareService<S>;

    fn create(&self, service: S) -> Self::Service {
        SaCheckLoginMiddlewareService {
            service,
            state: self.state.clone(),
        }
    }
}

pub struct SaCheckLoginMiddlewareService<S> {
    service: S,
    state: SaTokenState,
}

impl<S, Err> Service<WebRequest<Err>> for SaCheckLoginMiddlewareService<S>
where
    S: Service<WebRequest<Err>, Response = WebResponse, Error = Error>,
    Err: ErrorRenderer,
{
    type Response = WebResponse;
    type Error = Error;

    async fn call(
        &self,
        req: WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        let adapter =
            NtexCapturedRequest::capture(&req, self.state.manager.config.token_name.as_str());
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        if flow.token.is_none() || flow.login_id.is_none() {
            return Err(WebError::from(InternalError::new(
                json!({
                    "code": 401,
                    "message": messages::AUTH_ERROR
                })
                .to_string(),
                ntex::http::StatusCode::UNAUTHORIZED,
            )));
        }

        if let Some(ref t) = flow.token {
            req.extensions_mut().insert(t.clone());
        }
        if let Some(ref id) = flow.login_id {
            req.extensions_mut().insert(SaLoginId(id.clone()));
        }

        flow.run(ctx.call(&self.service, req)).await
    }
}

/// sa-token 权限检查中间件 - 强制要求特定权限
///
/// 此中间件会检查用户是否拥有指定权限，如果没有则返回403错误
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

impl<S> Middleware<S> for SaCheckPermissionMiddleware {
    type Service = SaCheckPermissionMiddlewareService<S>;

    fn create(&self, service: S) -> Self::Service {
        SaCheckPermissionMiddlewareService {
            service,
            state: self.state.clone(),
            permission: self.permission.clone(),
        }
    }
}

pub struct SaCheckPermissionMiddlewareService<S> {
    service: S,
    state: SaTokenState,
    permission: String,
}

impl<S, Err> Service<WebRequest<Err>> for SaCheckPermissionMiddlewareService<S>
where
    S: Service<WebRequest<Err>, Response = WebResponse, Error = Error>,
    Err: ErrorRenderer,
{
    type Response = WebResponse;
    type Error = Error;

    async fn call(
        &self,
        req: WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        let adapter =
            NtexCapturedRequest::capture(&req, self.state.manager.config.token_name.as_str());
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        let Some(login_id) = flow.login_id.clone() else {
            return Err(WebError::from(InternalError::new(
                json!({
                    "code": 403,
                    "message": messages::PERMISSION_REQUIRED
                })
                .to_string(),
                ntex::http::StatusCode::FORBIDDEN,
            )));
        };

        if !StpUtil::has_permission(&login_id, &self.permission).await {
            return Err(WebError::from(InternalError::new(
                json!({
                    "code": 403,
                    "message": messages::PERMISSION_REQUIRED
                })
                .to_string(),
                ntex::http::StatusCode::FORBIDDEN,
            )));
        }

        if let Some(ref t) = flow.token {
            req.extensions_mut().insert(t.clone());
        }
        req.extensions_mut().insert(SaLoginId(login_id));

        flow.run(ctx.call(&self.service, req)).await
    }
}

/// sa-token 角色检查中间件 - 强制要求特定角色
///
/// 此中间件会检查用户是否拥有指定角色，如果没有则返回403错误
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

impl<S> Middleware<S> for SaCheckRoleMiddleware {
    type Service = SaCheckRoleMiddlewareService<S>;

    fn create(&self, service: S) -> Self::Service {
        SaCheckRoleMiddlewareService {
            service,
            state: self.state.clone(),
            role: self.role.clone(),
        }
    }
}

pub struct SaCheckRoleMiddlewareService<S> {
    service: S,
    state: SaTokenState,
    role: String,
}

impl<S, Err> Service<WebRequest<Err>> for SaCheckRoleMiddlewareService<S>
where
    S: Service<WebRequest<Err>, Response = WebResponse, Error = Error>,
    Err: ErrorRenderer,
{
    type Response = WebResponse;
    type Error = Error;

    async fn call(
        &self,
        req: WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        let adapter =
            NtexCapturedRequest::capture(&req, self.state.manager.config.token_name.as_str());
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        let Some(login_id) = flow.login_id.clone() else {
            return Err(WebError::from(InternalError::new(
                json!({
                    "code": 403,
                    "message": messages::ROLE_REQUIRED
                })
                .to_string(),
                ntex::http::StatusCode::FORBIDDEN,
            )));
        };

        if !StpUtil::has_role(&login_id, &self.role).await {
            return Err(WebError::from(InternalError::new(
                json!({
                    "code": 403,
                    "message": messages::ROLE_REQUIRED
                })
                .to_string(),
                ntex::http::StatusCode::FORBIDDEN,
            )));
        }

        if let Some(ref t) = flow.token {
            req.extensions_mut().insert(t.clone());
        }
        req.extensions_mut().insert(SaLoginId(login_id));

        flow.run(ctx.call(&self.service, req)).await
    }
}

/// 中文 | English
/// 权限验证中间件 - 验证用户是否拥有指定权限 | Permission middleware - verify if user has specified permissions
///
/// 注意：此中间件已废弃，建议使用 SaCheckPermissionMiddleware
#[deprecated(note = "Use SaCheckPermissionMiddleware instead")]
pub struct PermissionMiddleware {
    permission: String,
}

#[allow(deprecated)]
impl PermissionMiddleware {
    /// 中文 | English
    /// 创建权限验证中间件 | Create permission middleware
    pub fn new(permission: impl Into<String>) -> Self {
        Self {
            permission: permission.into(),
        }
    }
}

#[allow(deprecated)]
impl<S> Middleware<S> for PermissionMiddleware {
    type Service = PermissionMiddlewareService<S>;

    fn create(&self, service: S) -> Self::Service {
        PermissionMiddlewareService {
            service,
            permission: self.permission.clone(),
        }
    }
}

pub struct PermissionMiddlewareService<S> {
    service: S,
    permission: String,
}

impl<S, Err> Service<WebRequest<Err>> for PermissionMiddlewareService<S>
where
    S: Service<WebRequest<Err>, Response = WebResponse, Error = Error>,
    Err: ErrorRenderer,
{
    type Response = WebResponse;
    type Error = Error;

    async fn call(
        &self,
        req: WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        // 中文 | English
        // 注意：此方法已废弃，建议使用 SaCheckPermissionMiddleware
        // Note: This method is deprecated, use SaCheckPermissionMiddleware instead

        // 首先尝试从扩展数据获取 login_id（可能由其他中间件设置）
        // First try to get login_id from extensions (may be set by other middleware)
        let login_id_ext = req.extensions().get::<String>().cloned();
        if let Some(login_id) = login_id_ext {
            // 验证权限 | Verify permission
            if StpUtil::has_permission(&login_id, &self.permission).await {
                return ctx.call(&self.service, req).await;
            }
        } else {
            // 如果扩展中没有 login_id，尝试从请求中提取 token 并验证
            // If no login_id in extensions, try to extract token from request and verify
            if let Some(token_str) = extract_token_from_request_config(&req) {
                let token = TokenValue::new(token_str);

                // 简单验证 token 是否有效
                // Simple token validation
                if StpUtil::is_login(&token).await
                    && let Ok(login_id) = StpUtil::get_login_id(&token).await
                {
                    // 验证权限 | Verify permission
                    if StpUtil::has_permission(&login_id, &self.permission).await {
                        // 将 login_id 存储到扩展中供后续使用
                        // Store login_id in extensions for later use
                        req.extensions_mut().insert(SaLoginId(login_id));
                        return ctx.call(&self.service, req).await;
                    }
                }
            }
        }

        // 无权限或未登录，返回 403 | No permission or not logged in, return 403
        Err(WebError::from(InternalError::new(
            json!({
                "code": 403,
                "message": messages::PERMISSION_REQUIRED
            })
            .to_string(),
            ntex::http::StatusCode::FORBIDDEN,
        )))
    }
}

/// 废弃权限中间件用的 token 提取：走 `token_io::read_token`，尊重 `is_read_*` / 前缀。
/// Token extract for the deprecated permission middleware via `token_io::read_token`.
fn extract_token_from_request_config<Err>(req: &WebRequest<Err>) -> Option<String>
where
    Err: ErrorRenderer,
{
    let manager = StpUtil::try_get_manager().ok()?;
    let token_name = manager.config.token_name.as_str();
    let adapter = NtexCapturedRequest::capture(req, token_name);
    sa_token_core::token_io::read_token(&adapter, &manager.config)
}
