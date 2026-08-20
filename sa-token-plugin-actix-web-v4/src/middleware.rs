// Author: 金书记
//
//! Actix-web中间件

use actix_web::{
    Error, HttpMessage,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    error::ErrorUnauthorized,
};
use sa_token_core::router::run_auth_flow;
use sa_token_plugin_common::{SaLoginId, SaTokenState, rejection};
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;

use crate::adapter::ActixRequestAdapter;

/// sa-token 基础中间件 - 提取并验证 token
use sa_token_core::router::PathAuthConfig;

/// Sa-Token middleware with optional path-based authentication
/// 支持可选路径鉴权的 Sa-Token 中间件
pub struct SaTokenMiddleware {
    pub state: SaTokenState,
    /// Optional path authentication configuration
    /// 可选的路径鉴权配置
    pub path_config: Option<PathAuthConfig>,
}

impl SaTokenMiddleware {
    /// Create middleware without path authentication
    /// 创建不带路径鉴权的中间件
    pub fn new(state: SaTokenState) -> Self {
        Self {
            state,
            path_config: None,
        }
    }

    /// Create middleware with path-based authentication
    /// 创建带路径鉴权的中间件
    pub fn with_path_auth(state: SaTokenState, config: PathAuthConfig) -> Self {
        Self {
            state,
            path_config: Some(config),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SaTokenMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SaTokenMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SaTokenMiddlewareService {
            service: Rc::new(service),
            state: self.state.clone(),
            path_config: self.path_config.clone(),
        }))
    }
}

/// Sa-Token middleware service for Actix-web
/// Actix-web 的 Sa-Token 中间件服务
pub struct SaTokenMiddlewareService<S> {
    service: Rc<S>,
    state: SaTokenState,
    /// Optional path authentication configuration
    /// 可选的路径鉴权配置
    path_config: Option<PathAuthConfig>,
}

impl<S, B> Service<ServiceRequest> for SaTokenMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let state = self.state.clone();
        let path_config = self.path_config.clone();

        Box::pin(async move {
            let adapter = ActixRequestAdapter::new(req.request());
            let flow = run_auth_flow(&adapter, &state.manager, path_config.as_ref()).await;

            if flow.should_reject() {
                return Err(ErrorUnauthorized(
                    rejection::unauthorized_json().to_string(),
                ));
            }

            if let Some(t) = &flow.token {
                req.extensions_mut().insert(t.clone());
            }
            if let Some(id) = &flow.login_id {
                req.extensions_mut().insert(SaLoginId(id.clone()));
            }
            req.extensions_mut().insert(flow.context.clone());

            flow.run(service.call(req)).await
        })
    }
}

/// sa-token 登录检查中间件 - 强制要求登录
pub struct SaCheckLoginMiddleware {
    pub state: SaTokenState,
}

impl SaCheckLoginMiddleware {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SaCheckLoginMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SaCheckLoginMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SaCheckLoginMiddlewareService {
            service: Rc::new(service),
            state: self.state.clone(),
        }))
    }
}

pub struct SaCheckLoginMiddlewareService<S> {
    service: Rc<S>,
    state: SaTokenState,
}

impl<S, B> Service<ServiceRequest> for SaCheckLoginMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let state = self.state.clone();

        Box::pin(async move {
            let adapter = ActixRequestAdapter::new(req.request());
            let flow = run_auth_flow(&adapter, &state.manager, None).await;

            if flow.token.is_none() || flow.login_id.is_none() {
                return Err(ErrorUnauthorized(
                    rejection::unauthorized_json().to_string(),
                ));
            }

            if let Some(t) = &flow.token {
                req.extensions_mut().insert(t.clone());
            }
            if let Some(id) = &flow.login_id {
                req.extensions_mut().insert(SaLoginId(id.clone()));
            }
            req.extensions_mut().insert(flow.context.clone());

            flow.run(service.call(req)).await
        })
    }
}

/// 从请求中提取 token
pub fn extract_token_from_request(req: &ServiceRequest, state: &SaTokenState) -> Option<String> {
    let adapter = ActixRequestAdapter::new(req.request());
    sa_token_core::router::extract_token_from(&adapter, &state.manager.config)
}
