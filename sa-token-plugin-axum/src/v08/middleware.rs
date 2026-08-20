// Author: 金书记
//
//! Axum 0.8 check-login / check-permission middleware.

use std::task::{Context, Poll};

use http::{Request, Response, StatusCode};
use sa_token_plugin_common::{
    CONTENT_TYPE_JSON, SaLoginId, forbidden_json, unauthorized_json, write_json_body,
};
use tower::{Layer, Service};
use tower_08 as tower;

/// Layer that installs [`SaCheckLoginMiddleware`].
#[derive(Clone)]
pub struct SaCheckLoginLayer;

impl Default for SaCheckLoginLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl SaCheckLoginLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for SaCheckLoginLayer {
    type Service = SaCheckLoginMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SaCheckLoginMiddleware { inner }
    }
}

/// Requires an authenticated user (`SaLoginId` in request extensions).
#[derive(Clone)]
pub struct SaCheckLoginMiddleware<S> {
    inner: S,
}

/// Layer for [`SaCheckPermissionMiddleware`].
#[derive(Clone)]
pub struct SaCheckPermissionLayer {
    permission: String,
}

impl SaCheckPermissionLayer {
    pub fn new(permission: impl Into<String>) -> Self {
        Self {
            permission: permission.into(),
        }
    }
}

impl<S> Layer<S> for SaCheckPermissionLayer {
    type Service = SaCheckPermissionMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SaCheckPermissionMiddleware {
            inner,
            permission: self.permission.clone(),
        }
    }
}

/// Permission gate middleware.
#[derive(Clone)]
pub struct SaCheckPermissionMiddleware<S> {
    inner: S,
    permission: String,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SaCheckLoginMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body + From<Vec<u8>> + Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if request.extensions().get::<SaLoginId>().is_none() {
                let body_bytes = write_json_body(&unauthorized_json());
                let mut response = Response::new(ResBody::from(body_bytes));
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static(CONTENT_TYPE_JSON),
                );
                return Ok(response);
            }

            inner.call(request).await
        })
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SaCheckPermissionMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body + From<Vec<u8>> + Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let permission = self.permission.clone();

        Box::pin(async move {
            if let Some(sa_login_id) = request.extensions().get::<SaLoginId>()
                && sa_token_core::StpUtil::has_permission(sa_login_id.as_str(), &permission).await
            {
                return inner.call(request).await;
            }

            let body_bytes = write_json_body(&forbidden_json(None));
            let mut response = Response::new(ResBody::from(body_bytes));
            *response.status_mut() = StatusCode::FORBIDDEN;
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static(CONTENT_TYPE_JSON),
            );

            Ok(response)
        })
    }
}
