//! Tonic gRPC plugin integration tests.
//!
//! Tests TonicCapturedRequest, run_auth_flow with PathAuthConfig,
//! and get_login_id_from_request.

mod common;

use std::sync::Arc;

use sa_token_adapter::SaRequest;
use sa_token_core::router::{PathAuthConfig, run_auth_flow};
use sa_token_core::{SaTokenConfig, StpUtil, config::TokenStyle};
use sa_token_plugin_tonic::{
    SaTokenLoginId, SaTokenState, TonicCapturedRequest, get_login_id_from_request,
};
use sa_token_storage_memory::MemoryStorage;

static MANAGER: std::sync::OnceLock<Arc<sa_token_core::SaTokenManager>> =
    std::sync::OnceLock::new();

fn init_manager() -> Arc<sa_token_core::SaTokenManager> {
    MANAGER
        .get_or_init(|| {
            let storage = Arc::new(MemoryStorage::new());
            let config = SaTokenConfig::builder()
                .token_name("satoken")
                .timeout(3600)
                .token_style(TokenStyle::Uuid)
                .build_config();
            let manager = sa_token_core::SaTokenManager::new(storage, config);
            let _ = StpUtil::try_init_manager(manager.clone());
            Arc::new(manager)
        })
        .clone()
}

fn test_state() -> SaTokenState {
    SaTokenState {
        manager: init_manager(),
    }
}

fn make_captured_request(path: &str, token: Option<&str>) -> TonicCapturedRequest {
    let mut builder = http::Request::builder().uri(path).method("POST");
    if let Some(t) = token {
        builder = builder.header("satoken", format!("Bearer {}", t));
    }
    let req = builder.body(()).unwrap();
    TonicCapturedRequest::from_http(&req)
}

// ============================================================================
// 修复 #4: metadata 解析不含 Debug 引号
// ============================================================================

#[test]
fn test_captured_request_header_no_debug_quotes() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("satoken", "Bearer abc123".parse().unwrap());

    let captured = TonicCapturedRequest::from_metadata(
        &metadata,
        "/auth.AuthService/GetUserInfo".to_string(),
        "GRPC",
    );

    let header = captured.get_header("satoken").unwrap();
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

// ============================================================================
// 修复 #3: PathAuthConfig 控制公开/受保护 RPC
// ============================================================================

#[tokio::test]
async fn test_path_config_public_rpc_no_token_ok() {
    let state = test_state();
    let path_config = PathAuthConfig::new()
        .include(vec!["/auth.AuthService/**".to_string()])
        .exclude(vec![
            "/auth.AuthService/HealthCheck".to_string(),
            "/auth.AuthService/Login".to_string(),
        ]);

    let captured = make_captured_request("/auth.AuthService/HealthCheck", None);
    let flow = run_auth_flow(&captured, &state.manager, Some(&path_config)).await;

    assert!(!flow.should_reject());
}

#[tokio::test]
async fn test_path_config_public_login_no_token_ok() {
    let state = test_state();
    let path_config = PathAuthConfig::new()
        .include(vec!["/auth.AuthService/**".to_string()])
        .exclude(vec![
            "/auth.AuthService/HealthCheck".to_string(),
            "/auth.AuthService/Login".to_string(),
        ]);

    let captured = make_captured_request("/auth.AuthService/Login", None);
    let flow = run_auth_flow(&captured, &state.manager, Some(&path_config)).await;

    assert!(!flow.should_reject());
}

#[tokio::test]
async fn test_path_config_protected_rpc_no_token_rejects() {
    let state = test_state();
    let path_config = PathAuthConfig::new()
        .include(vec!["/auth.AuthService/**".to_string()])
        .exclude(vec![
            "/auth.AuthService/HealthCheck".to_string(),
            "/auth.AuthService/Login".to_string(),
        ]);

    let captured = make_captured_request("/auth.AuthService/GetUserInfo", None);
    let flow = run_auth_flow(&captured, &state.manager, Some(&path_config)).await;

    assert!(flow.should_reject());
}

// ============================================================================
// 修复 #1 + #2: 有效 token 注入 login_id（非 token 字符串）
// ============================================================================

#[tokio::test]
async fn test_valid_token_returns_login_id_not_token_string() {
    let state = test_state();
    let token = state.manager.login("tonic_test_user").await.expect("login");
    let path_config = PathAuthConfig::new()
        .include(vec!["/auth.AuthService/**".to_string()])
        .exclude(vec!["/auth.AuthService/Login".to_string()]);

    let captured = make_captured_request("/auth.AuthService/GetUserInfo", Some(token.as_str()));
    let flow = run_auth_flow(&captured, &state.manager, Some(&path_config)).await;

    assert!(!flow.should_reject());
    assert_eq!(flow.login_id.as_deref(), Some("tonic_test_user"));
    assert_ne!(flow.login_id.as_deref(), Some(token.as_str()));
}

#[tokio::test]
async fn test_get_login_id_from_request_reads_typed_extension() {
    let mut request = tonic::Request::new(());
    assert!(get_login_id_from_request(&request).is_none());

    request
        .extensions_mut()
        .insert(SaTokenLoginId("typed_user".to_string()));
    assert_eq!(get_login_id_from_request(&request).unwrap(), "typed_user");

    request.extensions_mut().insert("raw_string".to_string());
    assert_eq!(get_login_id_from_request(&request).unwrap(), "typed_user");
}

// ============================================================================
// 修复 #1: 无效/过期 token 被拒绝
// ============================================================================

#[tokio::test]
async fn test_invalid_token_rejected() {
    let state = test_state();
    let path_config = PathAuthConfig::new()
        .include(vec!["/auth.AuthService/**".to_string()])
        .exclude(vec!["/auth.AuthService/Login".to_string()]);

    let captured =
        make_captured_request("/auth.AuthService/GetUserInfo", Some("invalid-token-abc"));
    let flow = run_auth_flow(&captured, &state.manager, Some(&path_config)).await;

    assert!(flow.should_reject());
    assert!(flow.login_id.is_none());
}
