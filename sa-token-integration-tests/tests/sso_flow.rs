//! P2: SSO Single Sign-On integration tests.
//!
//! Tests SSO ticket lifecycle: login → create ticket → validate → consume,
//! unified logout, timeout, and error paths.

mod common;

use sa_token_core::{SaTokenConfig, SaTokenError, SaTokenManager, SsoServer};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

fn sso_manager() -> Arc<SaTokenManager> {
    let storage = Arc::new(MemoryStorage::new());
    let config = SaTokenConfig::builder().timeout(3600).build_config();
    Arc::new(SaTokenManager::new(storage, config))
}

fn sso_server(manager: Arc<SaTokenManager>) -> SsoServer {
    let cfg = sa_token_core::SsoConfig::builder()
        .allow_cross_domain(true)
        .add_allowed_origin("http://app1.example.com".to_string())
        .add_allowed_origin("http://app2.example.com".to_string())
        .add_allowed_origin("http://app3.example.com".to_string())
        .build();
    SsoServer::new(manager).with_config(&cfg)
}

// ── Success cases: ticket lifecycle ───────────────────────────────────────

#[tokio::test]
async fn test_sso_server_login_returns_ticket() {
    let mgr = sso_manager();
    let server = sso_server(mgr.clone());
    // Login via SSO server — creates token + session + ticket
    let ticket = server
        .login(
            "user_sso".to_string(),
            "http://app1.example.com".to_string(),
        )
        .await
        .expect("login");
    assert!(!ticket.ticket_id.is_empty());
    assert_eq!(ticket.service, "http://app1.example.com");
    assert_eq!(ticket.login_id, "user_sso");
    assert!(!ticket.used);
}

#[tokio::test]
async fn test_sso_validate_ticket_returns_login_id() {
    let mgr = sso_manager();
    let server = sso_server(mgr.clone());
    let ticket = server
        .login(
            "user_val".to_string(),
            "http://app1.example.com".to_string(),
        )
        .await
        .expect("login");
    let login_id = server
        .validate_ticket(&ticket.ticket_id, "http://app1.example.com")
        .await
        .expect("validate");
    assert_eq!(login_id, "user_val");
}

#[tokio::test]
async fn test_ticket_is_consumed_after_validation() {
    let mgr = sso_manager();
    let server = sso_server(mgr.clone());
    let ticket = server
        .login(
            "user_consume".to_string(),
            "http://app1.example.com".to_string(),
        )
        .await
        .expect("login");
    // First validation succeeds
    server
        .validate_ticket(&ticket.ticket_id, "http://app1.example.com")
        .await
        .expect("first validate");
    // Second validation fails (ticket consumed / used=true)
    let result = server
        .validate_ticket(&ticket.ticket_id, "http://app1.example.com")
        .await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SaTokenError::TicketExpired));
}

#[tokio::test]
async fn test_is_logged_in_after_login() {
    let mgr = sso_manager();
    let server = sso_server(mgr.clone());
    server
        .login("user_li".to_string(), "http://app1.example.com".to_string())
        .await
        .expect("login");
    assert!(server.is_logged_in("user_li").await);
}

#[tokio::test]
async fn test_is_logged_in_false_for_unknown_user() {
    let mgr = sso_manager();
    let server = sso_server(mgr);
    assert!(!server.is_logged_in("no_such_user").await);
}

#[tokio::test]
async fn test_unified_logout_returns_client_list() {
    let mgr = sso_manager();
    let server = sso_server(mgr.clone());
    server
        .login(
            "user_out".to_string(),
            "http://app1.example.com".to_string(),
        )
        .await
        .expect("login");
    server
        .login(
            "user_out".to_string(),
            "http://app2.example.com".to_string(),
        )
        .await
        .expect("login2");
    let clients = server.logout("user_out").await.expect("logout");
    assert!(clients.contains(&"http://app1.example.com".to_string()));
    assert!(clients.contains(&"http://app2.example.com".to_string()));
    assert!(!server.is_logged_in("user_out").await);
}

#[tokio::test]
async fn test_multiple_clients_one_user() {
    let mgr = sso_manager();
    let server = sso_server(mgr.clone());
    server
        .login(
            "user_multi".to_string(),
            "http://app1.example.com".to_string(),
        )
        .await
        .expect("login1");
    server
        .login(
            "user_multi".to_string(),
            "http://app2.example.com".to_string(),
        )
        .await
        .expect("login2");
    // Each login creates a new ticket for that service
    let ticket3 = server
        .login(
            "user_multi".to_string(),
            "http://app3.example.com".to_string(),
        )
        .await
        .expect("login3");
    let login_id = server
        .validate_ticket(&ticket3.ticket_id, "http://app3.example.com")
        .await
        .expect("validate");
    assert_eq!(login_id, "user_multi");
    assert!(server.is_logged_in("user_multi").await);
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_validate_nonexistent_ticket() {
    let mgr = sso_manager();
    let server = sso_server(mgr);
    let result = server
        .validate_ticket("no_such_ticket_id", "http://app1.example.com")
        .await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SaTokenError::InvalidTicket));
}

#[tokio::test]
async fn test_validate_ticket_wrong_service_url() {
    let mgr = sso_manager();
    let server = sso_server(mgr.clone());
    let ticket = server
        .login(
            "user_svc".to_string(),
            "http://app1.example.com".to_string(),
        )
        .await
        .expect("login");
    let result = server
        .validate_ticket(&ticket.ticket_id, "http://wrong-service.example.com")
        .await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SaTokenError::ServiceMismatch));
}

#[tokio::test]
async fn test_ticket_expires_after_timeout() {
    let mgr = sso_manager();
    let server = sso_server(mgr.clone()).with_ticket_timeout(1); // 1-second TTL
    let ticket = server
        .login(
            "user_exp_sso".to_string(),
            "http://app1.example.com".to_string(),
        )
        .await
        .expect("login");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let result = server
        .validate_ticket(&ticket.ticket_id, "http://app1.example.com")
        .await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SaTokenError::TicketExpired));
}

#[tokio::test]
async fn test_logout_unknown_user_returns_empty() {
    let mgr = sso_manager();
    let server = sso_server(mgr);
    let clients = server.logout("unknown_user").await.expect("logout");
    assert!(clients.is_empty());
}

#[tokio::test]
async fn test_check_ticket_returns_remain_seconds() {
    let mgr = sso_manager();
    let server = sso_server(mgr.clone());
    let ticket = server
        .login(
            "user_chk".to_string(),
            "http://app1.example.com".to_string(),
        )
        .await
        .expect("login");
    let result = server
        .check_ticket(&ticket.ticket_id, "http://app1.example.com")
        .await
        .expect("check_ticket");
    assert_eq!(result.login_id, "user_chk");
    assert!(result.remain_seconds > 0);
    // check_ticket 不消费，仍可 validate
    server
        .validate_ticket(&ticket.ticket_id, "http://app1.example.com")
        .await
        .expect("validate after check");
}

#[tokio::test]
async fn test_logout_with_slo_returns_logout_urls() {
    let mgr = sso_manager();
    let server = sso_server(mgr.clone());
    server
        .login(
            "user_slo".to_string(),
            "http://app1.example.com".to_string(),
        )
        .await
        .expect("login");
    let urls = server.logout_with_slo("user_slo").await.expect("slo");
    assert_eq!(urls.len(), 1);
    assert!(urls[0].contains("sso/logout"));
    assert!(urls[0].contains("slo=1"));
}

#[tokio::test]
async fn test_create_ticket_rejects_disallowed_origin() {
    let mgr = sso_manager();
    let config = sa_token_core::SsoConfig::builder()
        .allow_cross_domain(true)
        .allowed_origins(vec!["http://allowed.example.com".to_string()])
        .build();
    let server = sso_server(mgr).with_config(&config);
    let result = server
        .create_ticket("u1".to_string(), "http://evil.example.com".to_string())
        .await;
    assert!(matches!(result, Err(SaTokenError::ServiceMismatch)));
}
