//! SSO ticket / origin / SLO 集成测试。

mod common;

use common::setup;
use sa_token_core::sso::{SsoConfig, SsoManager, SsoServer};

#[tokio::test]
async fn test_create_and_validate_ticket() {
    let mgr = setup::fresh_manager();
    let sso = SsoServer::new(mgr).with_ticket_timeout(120);
    let ticket = sso
        .create_ticket("user_sso".into(), "https://app.example".into())
        .await
        .expect("ticket");
    let login_id = sso
        .validate_ticket(&ticket.ticket_id, "https://app.example")
        .await
        .expect("validate");
    assert_eq!(login_id, "user_sso");
}

#[tokio::test]
async fn test_ticket_wrong_service_rejected() {
    let mgr = setup::fresh_manager();
    let sso = SsoServer::new(mgr).with_ticket_timeout(120);
    let ticket = sso
        .create_ticket("user_sso".into(), "https://app.example".into())
        .await
        .expect("ticket");
    let bad = sso
        .validate_ticket(&ticket.ticket_id, "https://other.example")
        .await;
    assert!(bad.is_err());
}

#[tokio::test]
async fn test_cross_origin_login_blocked_when_whitelist_enabled() {
    let mgr = setup::fresh_manager();
    let config = SsoConfig::builder()
        .server_url("https://sso.example")
        .allow_cross_domain(true)
        .allowed_origins(vec!["https://app.example".into()])
        .build();
    let sso = SsoServer::new(mgr).with_config(&config);
    assert!(!sso.is_allowed_origin("https://evil.example"));
    assert!(sso.is_allowed_origin("https://app.example"));
    let login = sso
        .login("user_x".into(), "https://evil.example".into())
        .await;
    assert!(
        login.is_err(),
        "cross-origin login must be rejected when not in whitelist"
    );
    let ok = sso
        .login("user_x".into(), "https://app.example".into())
        .await
        .expect("allowed origin login");
    assert!(!ok.ticket_id.is_empty());
}

#[tokio::test]
async fn test_slo_invalidates_client_tickets() {
    let mgr = setup::fresh_manager();
    let sso = SsoServer::new(mgr).with_ticket_timeout(120);
    let t1 = sso
        .login("user_slo".into(), "https://a.example".into())
        .await
        .expect("login a");
    let t2 = sso
        .login("user_slo".into(), "https://b.example".into())
        .await
        .expect("login b");
    let _urls = sso.logout_with_slo("user_slo").await.expect("slo");
    assert!(
        sso.validate_ticket(&t1.ticket_id, "https://a.example")
            .await
            .is_err()
    );
    assert!(
        sso.validate_ticket(&t2.ticket_id, "https://b.example")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_sso_manager_facade() {
    let config = SsoConfig::builder()
        .server_url("https://sso.example")
        .ticket_timeout(60)
        .build();
    let facade = SsoManager::new(config);
    assert_eq!(facade.config().server_url, "https://sso.example");
}
