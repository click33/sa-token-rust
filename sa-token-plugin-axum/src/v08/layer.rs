// Author: 金书记
//
//! Axum **0.8** Tower `Layer`：`AxumRequestSnapshot` + **`run_auth_flow`**（可选 **`PathAuthConfig`**）。

use http::{Request, Response};
use sa_token_core::{router::PathAuthConfig, router::run_auth_flow};
use sa_token_plugin_common::{
    CONTENT_TYPE_JSON, SaTokenHttpStatus, SaTokenState, apply_to_typed_extensions,
    unauthorized_json, write_json_body,
};
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};
use tower_08 as tower;

use crate::shared::adapter::AxumRequestSnapshot;

/// Sa-Token layer with optional path-based authentication.
#[derive(Clone)]
pub struct SaTokenLayer {
    state: SaTokenState,
    path_config: Option<PathAuthConfig>,
}

impl SaTokenLayer {
    pub fn new(state: SaTokenState) -> Self {
        Self {
            state,
            path_config: None,
        }
    }

    pub fn with_path_auth(state: SaTokenState, config: PathAuthConfig) -> Self {
        Self {
            state,
            path_config: Some(config),
        }
    }
}

impl<S> Layer<S> for SaTokenLayer {
    type Service = SaTokenMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SaTokenMiddleware {
            inner,
            state: self.state.clone(),
            path_config: self.path_config.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SaTokenMiddleware<S> {
    pub(crate) inner: S,
    pub(crate) state: SaTokenState,
    pub(crate) path_config: Option<PathAuthConfig>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SaTokenMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body + From<Vec<u8>> + Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let state = self.state.clone();
        let path_config = self.path_config.clone();

        Box::pin(async move {
            let snapshot = AxumRequestSnapshot::capture(&request);
            let flow = run_auth_flow(&snapshot, &state.manager, path_config.as_ref()).await;

            if flow.should_reject() {
                let body_bytes = write_json_body(&unauthorized_json());
                let mut response = Response::new(ResBody::from(body_bytes));
                *response.status_mut() =
                    http::StatusCode::from_u16(SaTokenHttpStatus::Unauthorized as u16)
                        .unwrap_or(http::StatusCode::UNAUTHORIZED);
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static(CONTENT_TYPE_JSON),
                );
                return Ok(response);
            }

            apply_to_typed_extensions(request.extensions_mut(), &flow);

            flow.run(inner.call(request)).await
        })
    }
}
