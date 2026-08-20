//! P2: Axum framework plugin integration tests.
//!
//! Tests SaTokenLayer, SaCheckLoginLayer, SaCheckPermissionLayer middleware,
//! LoginIdExtractor, and token-injection into request extensions.

mod common;

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, to_bytes};
use axum_08 as axum;
use http::{Request, Response, StatusCode};
use tower::{Layer, Service, ServiceExt};
use tower_08 as tower;

use sa_token_core::{SaTokenConfig, StpUtil, config::TokenStyle};
use sa_token_plugin_axum::{
    SaCheckLoginLayer, SaCheckPermissionLayer, SaLoginId, SaTokenLayer, SaTokenState as AxumState,
};
use sa_token_storage_memory::MemoryStorage;

// OnceLock ensures StpUtil is initialized only once per test binary.
static MANAGER: std::sync::OnceLock<Arc<sa_token_core::SaTokenManager>> =
    std::sync::OnceLock::new();

fn init_manager() -> Arc<sa_token_core::SaTokenManager> {
    MANAGER
        .get_or_init(|| {
            let storage = Arc::new(MemoryStorage::new());
            let config = SaTokenConfig::builder()
                .token_name("sa-token")
                .timeout(3600)
                .token_style(TokenStyle::Uuid)
                .build_config();
            let manager = sa_token_core::SaTokenManager::new(storage, config);
            let _ = StpUtil::try_init_manager(manager.clone());
            Arc::new(manager)
        })
        .clone()
}

fn test_state() -> AxumState {
    AxumState::from_manager((*init_manager()).clone())
}

fn request_with_token(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("sa-token", token)
        .body(Body::empty())
        .unwrap()
}

fn request_without_token(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

// A service that returns the login_id from extensions.
#[derive(Clone)]
struct EchoLoginIdSvc;

impl Service<Request<Body>> for EchoLoginIdSvc {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        Box::pin(async move {
            let login_id = req
                .extensions()
                .get::<SaLoginId>()
                .map(|id| id.0.clone())
                .unwrap_or_else(|| "no_login".to_string());
            Ok(Response::new(Body::from(login_id)))
        })
    }
}

// ── Success cases: SaTokenLayer ────────────────────────────────────────────

#[tokio::test]
async fn test_sa_token_layer_passes_valid_token() {
    let state = test_state();
    let token = state.manager.login("axum_user").await.expect("login");
    let mut svc = SaTokenLayer::new(state).layer(EchoLoginIdSvc);

    let req = request_with_token("/api/data", token.as_str());
    let res = svc.ready().await.unwrap().call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"axum_user");
}

#[tokio::test]
async fn test_sa_token_layer_injects_token_into_extensions() {
    let state = test_state();
    let token = state.manager.login("axum_token_user").await.expect("login");
    let mut svc = SaTokenLayer::new(state).layer(EchoLoginIdSvc);

    let req = request_with_token("/api/data", token.as_str());
    let res = svc.ready().await.unwrap().call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    // The body should contain the login_id injected by the layer
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(std::str::from_utf8(&body).unwrap(), "axum_token_user");
}

#[tokio::test]
async fn test_sa_token_layer_allows_request_without_token() {
    let state = test_state();
    let mut svc = SaTokenLayer::new(state).layer(EchoLoginIdSvc);

    let req = request_without_token("/public/hello");
    let res = svc.ready().await.unwrap().call(req).await.unwrap();
    // Without path_config, no token means no rejection — just no login_id injected
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(std::str::from_utf8(&body).unwrap(), "no_login");
}

// ── Success cases: SaCheckLoginLayer ──────────────────────────────────────

#[tokio::test]
async fn test_check_login_layer_passes_when_login_id_present() {
    let state = test_state();
    let token = state.manager.login("axum_check").await.expect("login");
    // First run through SaTokenLayer to inject login_id
    let inner = SaCheckLoginLayer::new().layer(EchoLoginIdSvc);
    let mut svc = SaTokenLayer::new(state).layer(inner);

    let req = request_with_token("/api/protected", token.as_str());
    let res = svc.ready().await.unwrap().call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

// ── Success cases: SaCheckPermissionLayer ─────────────────────────────────

#[tokio::test]
async fn test_check_permission_layer_passes_with_correct_perm() {
    let state = test_state();
    let token = state.manager.login("axum_perm").await.expect("login");
    // Set permissions for this user
    StpUtil::set_permissions("axum_perm", vec!["admin:panel".to_string()])
        .await
        .unwrap();

    let inner = SaCheckPermissionLayer::new("admin:panel").layer(EchoLoginIdSvc);
    let mut svc = SaTokenLayer::new(state).layer(inner);

    let req = request_with_token("/admin/panel", token.as_str());
    let res = svc.ready().await.unwrap().call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

// ── Failure cases: SaTokenLayer with path auth ────────────────────────────

#[tokio::test]
async fn test_sa_token_layer_rejects_expired_token() {
    let storage = Arc::new(MemoryStorage::new());
    let config = SaTokenConfig::builder()
        .token_name("sa-token")
        .timeout(1)
        .build_config();
    let manager = sa_token_core::SaTokenManager::new(storage, config);
    let state = AxumState::from_manager(manager.clone());
    let token = manager.login("axum_exp").await.expect("login");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let mut svc = SaTokenLayer::new(state).layer(EchoLoginIdSvc);
    let req = request_with_token("/api/data", token.as_str());
    let res = svc.ready().await.unwrap().call(req).await.unwrap();
    // Expired token → is_valid=false, no login_id injected
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(std::str::from_utf8(&body).unwrap(), "no_login");
}

// ── Failure cases: SaCheckLoginLayer ──────────────────────────────────────

#[tokio::test]
async fn test_check_login_layer_returns_401_without_login_id() {
    let inner = SaCheckLoginLayer::new().layer(EchoLoginIdSvc);
    let mut svc = inner; // No SaTokenLayer → no login_id injected

    let req = Request::builder()
        .uri("/protected")
        .body(Body::empty())
        .unwrap();
    let res = svc.ready().await.unwrap().call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// ── Failure cases: SaCheckPermissionLayer ─────────────────────────────────

#[tokio::test]
async fn test_check_permission_layer_returns_403_without_permission() {
    let state = test_state();
    let token = state.manager.login("axum_noperm").await.expect("login");
    // User has NO permissions set

    let inner = SaCheckPermissionLayer::new("admin:panel").layer(EchoLoginIdSvc);
    let mut svc = SaTokenLayer::new(state).layer(inner);

    let req = request_with_token("/admin/panel", token.as_str());
    let res = svc.ready().await.unwrap().call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_check_permission_layer_returns_403_with_wrong_permission() {
    let state = test_state();
    let token = state.manager.login("axum_wrongperm").await.expect("login");
    StpUtil::set_permissions("axum_wrongperm", vec!["user:read".to_string()])
        .await
        .unwrap();

    let inner = SaCheckPermissionLayer::new("admin:panel").layer(EchoLoginIdSvc);
    let mut svc = SaTokenLayer::new(state).layer(inner);

    let req = request_with_token("/admin/panel", token.as_str());
    let res = svc.ready().await.unwrap().call(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
