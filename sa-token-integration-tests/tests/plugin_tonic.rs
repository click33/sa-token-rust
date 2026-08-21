//! Tonic 插件：用带/不带 Authorization 的 Request 测 `GrpcServerInterceptor`。
//!
//! 禁止只测 `check_permission`；login / add_permission 的 Result 必须断言。
//! 过期用灰盒拨钟，禁止 sleep。

mod common;

use common::setup;
use sa_token_adapter::SaRequest;
use sa_token_core::router::PathAuthConfig;
use sa_token_plugin_tonic::{
    GrpcServerInterceptor, SaTokenGrpcPath, SaTokenLoginId, SaTokenState,
    TonicCapturedRequest, check_permission, get_login_id_from_request,
};
use tonic::Request;
use tonic::service::Interceptor;

fn test_state() -> SaTokenState {
    let _ = setup::shared_manager();
    SaTokenState {
        manager: setup::shared_manager(),
    }
}

fn protected_path_config() -> PathAuthConfig {
    PathAuthConfig::new()
        .include(vec!["/auth.AuthService/**".to_string()])
        .exclude(vec![
            "/auth.AuthService/HealthCheck".to_string(),
            "/auth.AuthService/Login".to_string(),
        ])
}

/// 构造带 gRPC path 扩展的 Request（Interceptor 依赖 SaTokenGrpcPath）。
fn grpc_request(path: &str, authorization: Option<&str>) -> Request<()> {
    let mut req = Request::new(());
    req.extensions_mut()
        .insert(SaTokenGrpcPath(path.to_string()));
    if let Some(auth) = authorization {
        req.metadata_mut()
            .insert("authorization", auth.parse().expect("metadata value"));
    }
    req
}

// ── metadata 解析 ─────────────────────────────────────────────────────────

#[test]
fn test_captured_request_header_no_debug_quotes() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", "Bearer abc123".parse().unwrap());

    let captured = TonicCapturedRequest::from_metadata(
        &metadata,
        "/auth.AuthService/GetUserInfo".to_string(),
        "GRPC",
    );

    let header = captured.get_header("authorization").unwrap();
    assert_eq!(header, "Bearer abc123");
    assert!(!header.contains('"'));
}

#[test]
fn test_captured_request_header_case_insensitive() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", "Bearer xyz".parse().unwrap());

    let captured = TonicCapturedRequest::from_metadata(&metadata, "/test".to_string(), "GRPC");

    assert_eq!(captured.get_header("Authorization").unwrap(), "Bearer xyz");
    assert_eq!(captured.get_header("authorization").unwrap(), "Bearer xyz");
    assert_eq!(captured.get_header("AUTHORIZATION").unwrap(), "Bearer xyz");
}

#[tokio::test]
async fn test_get_login_id_from_request_reads_typed_extension() {
    let mut request = Request::new(());
    assert!(get_login_id_from_request(&request).is_none());

    request
        .extensions_mut()
        .insert(SaTokenLoginId("typed_user".to_string()));
    assert_eq!(get_login_id_from_request(&request).unwrap(), "typed_user");
}

// ── GrpcServerInterceptor（真实 Request）──────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_interceptor_rejects_without_authorization() {
    let state = test_state();
    let mut interceptor =
        GrpcServerInterceptor::with_path_auth(state, protected_path_config());

    let req = grpc_request("/auth.AuthService/GetUserInfo", None);
    let err = interceptor
        .call(req)
        .expect_err("protected RPC without Authorization must fail");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_interceptor_allows_excluded_path_without_token() {
    let state = test_state();
    let mut interceptor =
        GrpcServerInterceptor::with_path_auth(state, protected_path_config());

    let req = grpc_request("/auth.AuthService/HealthCheck", None);
    let out = interceptor
        .call(req)
        .expect("excluded HealthCheck must pass without token");
    assert!(get_login_id_from_request(&out).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_interceptor_injects_login_id_with_authorization_bearer() {
    let state = test_state();
    let id = setup::unique_login_id("tonic_user");
    let token = state.manager.login(&id).await.expect("login");

    let mut interceptor =
        GrpcServerInterceptor::with_path_auth(state, protected_path_config());
    let req = grpc_request(
        "/auth.AuthService/GetUserInfo",
        Some(&format!("Bearer {}", token.as_str())),
    );
    let out = interceptor
        .call(req)
        .expect("valid Authorization must pass");
    assert_eq!(get_login_id_from_request(&out).as_deref(), Some(id.as_str()));
    assert_ne!(get_login_id_from_request(&out).as_deref(), Some(token.as_str()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_interceptor_rejects_invalid_token() {
    let state = test_state();
    let mut interceptor =
        GrpcServerInterceptor::with_path_auth(state, protected_path_config());

    let req = grpc_request(
        "/auth.AuthService/GetUserInfo",
        Some("Bearer invalid-token-abc"),
    );
    let err = interceptor
        .call(req)
        .expect_err("invalid token must be Unauthenticated");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_interceptor_rejects_expired_token() {
    let mgr = setup::fresh_manager();
    let state = SaTokenState {
        manager: mgr.clone(),
    };
    let id = setup::unique_login_id("tonic_exp");
    let token = mgr.login(&id).await.expect("login");
    setup::expire_token(&mgr, &token).await;

    let mut interceptor =
        GrpcServerInterceptor::with_path_auth(state, protected_path_config());
    let req = grpc_request(
        "/auth.AuthService/GetUserInfo",
        Some(&format!("Bearer {}", token.as_str())),
    );
    let err = interceptor
        .call(req)
        .expect_err("expired token must be Unauthenticated");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

// ── check_permission：login / add_permission 必须断言 Result ──────────────

#[tokio::test]
async fn test_check_permission_after_asserted_login_and_grant() {
    let _ = setup::shared_manager();
    let id = setup::unique_login_id("tonic_perm");
    let _token = sa_token_core::StpUtil::login(&id)
        .await
        .expect("login must succeed");
    assert!(
        !check_permission(&id, "user:read").await,
        "permission must be absent before grant"
    );
    sa_token_core::StpUtil::add_permission(&id, "user:read")
        .await
        .expect("add_permission must succeed");
    assert!(
        check_permission(&id, "user:read").await,
        "permission must be present after grant"
    );
}
