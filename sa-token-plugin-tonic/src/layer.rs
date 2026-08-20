// Author: 金书记
//
// 中文 | English
// gRPC Tower 异步鉴权层 | gRPC Tower async authentication layer
//
//! 中文: 推荐的 gRPC 鉴权方式，支持异步 `run_auth_flow` + `PathAuthConfig` 路径级控制
//! English: Recommended gRPC auth approach, supports async `run_auth_flow` + `PathAuthConfig` path-level control

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{Request, Response, StatusCode};
use http_body::Body;
use sa_token_core::router::{PathAuthConfig, run_auth_flow};
use tower::{Layer, Service};

use crate::adapter::TonicCapturedRequest;
use crate::error::{SaTokenBearerToken, SaTokenGrpcPath, SaTokenLoginId};
use sa_token_adapter::SaRequest;
use sa_token_plugin_common::SaTokenState;

// ============================================================================
// 中文: Tower Layer
// English: Tower Layer
// ============================================================================

/// 中文: gRPC 服务端 Tower 鉴权层（推荐方式）
/// English: gRPC server Tower authentication layer (recommended)
///
/// 中文: 与 Axum 的 `SaTokenLayer` 设计一致，支持 `PathAuthConfig` per-RPC 鉴权规则
/// English: Consistent with Axum's `SaTokenLayer` design, supports `PathAuthConfig` per-RPC auth rules
#[derive(Clone)]
pub struct SaTokenGrpcLayer {
    state: SaTokenState,
    path_config: Option<PathAuthConfig>,
}

impl SaTokenGrpcLayer {
    /// 中文: 无路径规则，仅校验 token 并填充上下文（不拒绝请求）
    /// English: No path rules, only validate token and populate context (no rejection)
    pub fn new(state: SaTokenState) -> Self {
        Self {
            state,
            path_config: None,
        }
    }

    /// 中文: 启用 per-RPC 包含/排除规则（Ant 风格，path 为 gRPC URI path）
    /// English: Enable per-RPC include/exclude rules (Ant-style, path is gRPC URI path)
    ///
    /// 中文: gRPC URI path 格式为 `/<package>.<Service>/<Method>`
    /// English: gRPC URI path format is `/<package>.<Service>/<Method>`
    pub fn with_path_auth(state: SaTokenState, config: PathAuthConfig) -> Self {
        Self {
            state,
            path_config: Some(config),
        }
    }
}

// ============================================================================
// 中文: Tower Middleware
// English: Tower Middleware
// ============================================================================

/// 中文: gRPC Tower 鉴权中间件（由 `SaTokenGrpcLayer` 创建）
/// English: gRPC Tower auth middleware (created by `SaTokenGrpcLayer`)
#[derive(Clone)]
pub struct SaTokenGrpcMiddleware<S> {
    inner: S,
    state: SaTokenState,
    path_config: Option<PathAuthConfig>,
}

impl<S> Layer<S> for SaTokenGrpcLayer {
    type Service = SaTokenGrpcMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SaTokenGrpcMiddleware {
            inner,
            state: self.state.clone(),
            path_config: self.path_config.clone(),
        }
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SaTokenGrpcMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Body + Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let state = self.state.clone();
        let path_config = self.path_config.clone();

        Box::pin(async move {
            let captured = TonicCapturedRequest::from_http(&req);
            req.extensions_mut()
                .insert(SaTokenGrpcPath(captured.get_path()));
            let flow = run_auth_flow(&captured, &state.manager, path_config.as_ref()).await;

            if flow.should_reject() {
                let mut resp = Response::new(ResBody::default());
                *resp.status_mut() = StatusCode::UNAUTHORIZED;
                return Ok(resp);
            }

            if let Some(login_id) = flow.login_id.clone() {
                req.extensions_mut().insert(SaTokenLoginId(login_id));
            }
            if let Some(token) = flow.token.clone() {
                req.extensions_mut().insert(SaTokenBearerToken(token));
            }

            flow.run(inner.call(req)).await
        })
    }
}
