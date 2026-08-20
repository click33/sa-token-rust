// Author: 金书记
//
//! Poem 中间件实现

use crate::adapter::PoemRequestAdapter;
use poem_03::{
    Endpoint, IntoResponse, Middleware, Request, Response, Result as PoemResult, http::StatusCode,
};
use sa_token_core::router::run_auth_flow;
use sa_token_plugin_common::{SaLoginId, SaTokenState, rejection};

/// sa-token 基础中间件 - 提取并验证 token
pub struct SaTokenMiddleware {
    state: SaTokenState,
}

impl SaTokenMiddleware {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

impl<E: Endpoint> Middleware<E> for SaTokenMiddleware {
    type Output = SaTokenMiddlewareImpl<E>;

    fn transform(&self, ep: E) -> Self::Output {
        SaTokenMiddlewareImpl {
            ep,
            state: self.state.clone(),
        }
    }
}

pub struct SaTokenMiddlewareImpl<E> {
    ep: E,
    state: SaTokenState,
}

impl<E: Endpoint> Endpoint for SaTokenMiddlewareImpl<E> {
    type Output = Response;

    async fn call(&self, mut req: Request) -> PoemResult<Self::Output> {
        let adapter = PoemRequestAdapter::new(&req);
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        if let Some(t) = &flow.token {
            req.extensions_mut().insert(t.clone());
        }
        if let Some(id) = &flow.login_id {
            req.extensions_mut().insert(SaLoginId(id.clone()));
        }

        let result = flow.run(self.ep.call(req)).await;

        match result {
            Ok(resp) => Ok(resp.into_response()),
            Err(e) => Err(e),
        }
    }
}

/// sa-token 登录检查中间件 - 强制要求登录
pub struct SaCheckLoginMiddleware {
    state: SaTokenState,
}

impl SaCheckLoginMiddleware {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

impl<E: Endpoint> Middleware<E> for SaCheckLoginMiddleware {
    type Output = SaCheckLoginMiddlewareImpl<E>;

    fn transform(&self, ep: E) -> Self::Output {
        SaCheckLoginMiddlewareImpl {
            ep,
            state: self.state.clone(),
        }
    }
}

pub struct SaCheckLoginMiddlewareImpl<E> {
    ep: E,
    state: SaTokenState,
}

impl<E: Endpoint> Endpoint for SaCheckLoginMiddlewareImpl<E> {
    type Output = Response;

    async fn call(&self, mut req: Request) -> PoemResult<Self::Output> {
        let adapter = PoemRequestAdapter::new(&req);
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        if flow.token.is_none() || flow.login_id.is_none() {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Content-Type", rejection::CONTENT_TYPE_JSON)
                .body(rejection::unauthorized_json().to_string()));
        }

        if let Some(t) = &flow.token {
            req.extensions_mut().insert(t.clone());
        }
        if let Some(id) = &flow.login_id {
            req.extensions_mut().insert(SaLoginId(id.clone()));
        }

        let result = flow.run(self.ep.call(req)).await;

        match result {
            Ok(resp) => Ok(resp.into_response()),
            Err(e) => Err(e),
        }
    }
}
