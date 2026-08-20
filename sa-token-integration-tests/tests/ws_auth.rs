//! P3: WebSocket authentication integration tests.
//!
//! Tests WsAuthManager: authenticate with token from header/query,
//! verify_token, refresh_ws_session, and error paths.

mod common;

use sa_token_core::{SaTokenConfig, SaTokenError, SaTokenManager, WsAuthManager};
use sa_token_storage_memory::MemoryStorage;
use std::collections::HashMap;
use std::sync::Arc;

fn ws_manager() -> Arc<SaTokenManager> {
    let storage = Arc::new(MemoryStorage::new());
    let config = SaTokenConfig::builder()
        .token_name("sa-token")
        .timeout(3600)
        .build_config();
    Arc::new(SaTokenManager::new(storage, config))
}

// ── Success cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_authenticate_with_token_in_header() {
    let mgr = ws_manager();
    let token = mgr.login("ws_user").await.expect("login");
    let ws = WsAuthManager::new(mgr.clone());

    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        format!("Bearer {}", token.as_str()),
    );
    let query = HashMap::new();

    let auth = ws
        .authenticate(&headers, &query)
        .await
        .expect("authenticate");
    assert_eq!(auth.login_id, "ws_user");
    assert!(auth.session_id.starts_with("ws:ws_user:"));
    assert!(!auth.token.is_empty());
}

#[tokio::test]
async fn test_authenticate_with_token_in_query() {
    let mgr = ws_manager();
    let token = mgr.login("ws_query").await.expect("login");
    let ws = WsAuthManager::new(mgr.clone());

    let headers = HashMap::new();
    let mut query = HashMap::new();
    query.insert("token".to_string(), token.as_str().to_string());

    let auth = ws
        .authenticate(&headers, &query)
        .await
        .expect("authenticate via query");
    assert_eq!(auth.login_id, "ws_query");
}

#[tokio::test]
async fn test_verify_token_returns_login_id() {
    let mgr = ws_manager();
    let token = mgr.login("ws_verify").await.expect("login");
    let ws = WsAuthManager::new(mgr);
    let login_id = ws.verify_token(token.as_str()).await.expect("verify_token");
    assert_eq!(login_id, "ws_verify");
}

#[tokio::test]
async fn test_refresh_ws_session() {
    let mgr = ws_manager();
    let token = mgr.login("ws_refresh").await.expect("login");
    let ws = WsAuthManager::new(mgr.clone());

    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        format!("Bearer {}", token.as_str()),
    );
    let auth = ws
        .authenticate(&headers, &HashMap::new())
        .await
        .expect("authenticate");

    // Refresh should succeed
    ws.refresh_ws_session(&auth).await.expect("refresh");
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_authenticate_without_token_returns_not_login() {
    let mgr = ws_manager();
    let ws = WsAuthManager::new(mgr);
    let result = ws.authenticate(&HashMap::new(), &HashMap::new()).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SaTokenError::NotLogin));
}

#[tokio::test]
async fn test_authenticate_with_invalid_token() {
    let mgr = ws_manager();
    let ws = WsAuthManager::new(mgr);

    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Bearer invalid_token_value_12345678".to_string(),
    );
    let result = ws.authenticate(&headers, &HashMap::new()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_authenticate_with_expired_token() {
    let storage = Arc::new(MemoryStorage::new());
    let config = SaTokenConfig::builder()
        .timeout(1)
        .token_name("sa-token")
        .build_config();
    let mgr = Arc::new(SaTokenManager::new(storage, config));
    let token = mgr.login("ws_exp").await.expect("login");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let ws = WsAuthManager::new(mgr);
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        format!("Bearer {}", token.as_str()),
    );
    let result = ws.authenticate(&headers, &HashMap::new()).await;
    assert!(result.is_err(), "expired token should fail ws auth");
}

#[tokio::test]
async fn test_verify_token_with_invalid_token() {
    let mgr = ws_manager();
    let ws = WsAuthManager::new(mgr);
    let result = ws.verify_token("nonexistent_token_1234567890").await;
    assert!(result.is_err());
}
