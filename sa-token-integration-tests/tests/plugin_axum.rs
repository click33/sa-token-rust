//! Axum 插件：真实 Header / Cookie / Query / Bearer 注入、Layer 401、path_auth、宏运行时校验。
//!
//! 过期用灰盒拨钟（`expire_token`），禁止 sleep。

mod common;

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, to_bytes};
use axum_08 as axum;
use common::setup;
use http::{Request, Response, StatusCode};
use sa_token_core::{SaTokenResult, StpUtil, router::PathAuthConfig};
use sa_token_plugin_axum::{
    SaCheckLoginLayer, SaCheckPermissionLayer, SaLoginId, SaTokenLayer, SaTokenState as AxumState,
    sa_check_login,
};
use tower::{Layer, Service, ServiceExt};
use tower_08 as tower;

fn test_state() -> AxumState {
    let _ = setup::shared_manager();
    AxumState {
        manager: setup::shared_manager(),
    }
}

fn request_with_header_token(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("sa-token", token)
        .body(Body::empty())
        .expect("request")
}

fn request_with_cookie_token(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("cookie", format!("sa-token={token}"))
        .body(Body::empty())
        .expect("request")
}

fn request_with_query_token(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("{path}?sa-token={token}"))
        .body(Body::empty())
        .expect("request")
}

fn request_with_bearer_token(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

fn request_without_token(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).expect("request")
}

/// 回显 extensions 中的 login_id；无则 `no_login`。
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

/// 在 Layer 上下文内调用 `#[sa_check_login]`；失败映射为 HTTP 401。
#[derive(Clone)]
struct MacroCheckSvc;

#[sa_check_login]
async fn macro_guarded_ok() -> SaTokenResult<&'static str> {
    Ok("macro_ok")
}

impl Service<Request<Body>> for MacroCheckSvc {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        Box::pin(async move {
            match macro_guarded_ok().await {
                Ok(body) => Ok(Response::new(Body::from(body))),
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from("unauthorized"))
                    .expect("401 response")),
            }
        })
    }
}

async fn body_str(res: Response<Body>) -> String {
    let bytes = to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

// ── SaTokenLayer：注入渠道 ────────────────────────────────────────────────

#[tokio::test]
async fn test_sa_token_layer_injects_login_id_from_header() {
    let state = test_state();
    let id = setup::unique_login_id("axum_hdr");
    let token = state.manager.login(&id).await.expect("login");
    let mut svc = SaTokenLayer::new(state).layer(EchoLoginIdSvc);

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_header_token("/api/data", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_str(res).await, id);
}

#[tokio::test]
async fn test_sa_token_layer_injects_login_id_from_cookie() {
    let state = test_state();
    let id = setup::unique_login_id("axum_cookie");
    let token = state.manager.login(&id).await.expect("login");
    let mut svc = SaTokenLayer::new(state).layer(EchoLoginIdSvc);

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_cookie_token("/api/data", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_str(res).await, id);
}

#[tokio::test]
async fn test_sa_token_layer_injects_login_id_from_query() {
    let state = test_state();
    let id = setup::unique_login_id("axum_query");
    let token = state.manager.login(&id).await.expect("login");
    let mut svc = SaTokenLayer::new(state).layer(EchoLoginIdSvc);

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_query_token("/api/data", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_str(res).await, id);
}

#[tokio::test]
async fn test_sa_token_layer_injects_login_id_from_authorization_bearer() {
    let state = test_state();
    let id = setup::unique_login_id("axum_bearer");
    let token = state.manager.login(&id).await.expect("login");
    let mut svc = SaTokenLayer::new(state).layer(EchoLoginIdSvc);

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_bearer_token("/api/data", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_str(res).await, id);
}

#[tokio::test]
async fn test_sa_token_layer_allows_request_without_token() {
    let state = test_state();
    let mut svc = SaTokenLayer::new(state).layer(EchoLoginIdSvc);

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_without_token("/public/hello"))
        .await
        .expect("call");
    // 无 path_auth 时缺 token 不拒，只是不注入 login_id
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_str(res).await, "no_login");
}

/// 无 path_auth：过期 token 不注入 login_id，仍 200（勿命名为 rejects）。
#[tokio::test]
async fn test_sa_token_layer_expired_token_skips_login_id_without_path_auth() {
    let mgr = setup::fresh_manager();
    let state = AxumState {
        manager: mgr.clone(),
    };
    let id = setup::unique_login_id("axum_exp_skip");
    let token = mgr.login(&id).await.expect("login");
    setup::expire_token(&mgr, &token).await;

    let mut svc = SaTokenLayer::new(state).layer(EchoLoginIdSvc);
    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_header_token("/api/data", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_str(res).await, "no_login");
}

// ── SaCheckLoginLayer ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_check_login_layer_passes_when_login_id_present() {
    let state = test_state();
    let id = setup::unique_login_id("axum_check");
    let token = state.manager.login(&id).await.expect("login");
    let inner = SaCheckLoginLayer::new().layer(EchoLoginIdSvc);
    let mut svc = SaTokenLayer::new(state).layer(inner);

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_header_token("/api/protected", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_str(res).await, id);
}

#[tokio::test]
async fn test_check_login_layer_returns_401_without_login_id() {
    let mut svc = SaCheckLoginLayer::new().layer(EchoLoginIdSvc);

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_without_token("/protected"))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// SaTokenLayer 不注入过期 token 的 login_id → SaCheckLoginLayer 返回 401。
#[tokio::test]
async fn test_check_login_layer_returns_401_with_expired_token() {
    let mgr = setup::fresh_manager();
    let state = AxumState {
        manager: mgr.clone(),
    };
    let id = setup::unique_login_id("axum_exp_401");
    let token = mgr.login(&id).await.expect("login");
    setup::expire_token(&mgr, &token).await;

    let inner = SaCheckLoginLayer::new().layer(EchoLoginIdSvc);
    let mut svc = SaTokenLayer::new(state).layer(inner);
    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_header_token("/api/protected", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// ── path_auth：真实 Layer ─────────────────────────────────────────────────

#[tokio::test]
async fn test_path_auth_layer_include_exclude() {
    let state = test_state();
    let id = setup::unique_login_id("axum_path");
    let token = state.manager.login(&id).await.expect("login");
    let path = PathAuthConfig::new()
        .include(vec!["/api/**".into()])
        .exclude(vec!["/api/public/**".into()]);
    let mut svc = SaTokenLayer::with_path_auth(state, path).layer(EchoLoginIdSvc);

    // include 命中且无 token → 401
    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_without_token("/api/user"))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // exclude 命中 → 放行
    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_without_token("/api/public/info"))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_str(res).await, "no_login");

    // include + 有效 token → 注入 login_id
    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_header_token("/api/user", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_str(res).await, id);
}

#[tokio::test]
async fn test_path_auth_layer_rejects_expired_token() {
    let mgr = setup::fresh_manager();
    let state = AxumState {
        manager: mgr.clone(),
    };
    let id = setup::unique_login_id("axum_path_exp");
    let token = mgr.login(&id).await.expect("login");
    setup::expire_token(&mgr, &token).await;

    let path = PathAuthConfig::new().include(vec!["/api/**".into()]);
    let mut svc = SaTokenLayer::with_path_auth(state, path).layer(EchoLoginIdSvc);
    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_header_token("/api/user", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// ── 权限 Layer ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_check_permission_layer_passes_with_correct_perm() {
    let state = test_state();
    let id = setup::unique_login_id("axum_perm");
    let token = state.manager.login(&id).await.expect("login");
    StpUtil::set_permissions(&id, vec!["admin:panel".to_string()])
        .await
        .expect("set_permissions");

    let inner = SaCheckPermissionLayer::new("admin:panel").layer(EchoLoginIdSvc);
    let mut svc = SaTokenLayer::new(state).layer(inner);

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_header_token("/admin/panel", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_check_permission_layer_returns_403_without_permission() {
    let state = test_state();
    let id = setup::unique_login_id("axum_noperm");
    let token = state.manager.login(&id).await.expect("login");

    let inner = SaCheckPermissionLayer::new("admin:panel").layer(EchoLoginIdSvc);
    let mut svc = SaTokenLayer::new(state).layer(inner);

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_header_token("/admin/panel", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_check_permission_layer_returns_403_with_wrong_permission() {
    let state = test_state();
    let id = setup::unique_login_id("axum_wrongperm");
    let token = state.manager.login(&id).await.expect("login");
    StpUtil::set_permissions(&id, vec!["user:read".to_string()])
        .await
        .expect("set_permissions");

    let inner = SaCheckPermissionLayer::new("admin:panel").layer(EchoLoginIdSvc);
    let mut svc = SaTokenLayer::new(state).layer(inner);

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_header_token("/admin/panel", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

// ── #[sa_check_login] 运行时（非 compile-only）────────────────────────────

#[tokio::test]
async fn test_sa_check_login_macro_returns_401_without_token() {
    let _ = setup::shared_manager();
    // 直接调用：无上下文 → NotLogin
    setup::assert_err(macro_guarded_ok().await, "not_login");

    // HTTP：无 token 时 Layer 不写上下文，宏失败映射 401
    let state = test_state();
    let mut svc = SaTokenLayer::new(state).layer(MacroCheckSvc);
    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_without_token("/macro"))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_sa_check_login_macro_ok_with_valid_token() {
    let state = test_state();
    let id = setup::unique_login_id("axum_macro");
    let token = state.manager.login(&id).await.expect("login");
    let mut svc = SaTokenLayer::new(state).layer(MacroCheckSvc);

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(request_with_header_token("/macro", token.as_str()))
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_str(res).await, "macro_ok");
}
