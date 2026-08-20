//! P3: Distributed session integration tests.
//!
//! Tests DistributedSessionManager: service registration, session CRUD,
//! attributes, cross-service operations, and error paths.

mod common;

use chrono::Utc;
use sa_token_core::{
    DistributedSession, DistributedSessionManager, InMemoryDistributedStorage, SaTokenError,
    ServiceCredential,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

fn test_manager() -> DistributedSessionManager {
    DistributedSessionManager::new(
        Arc::new(InMemoryDistributedStorage::new()),
        "test-service".to_string(),
        Duration::from_secs(3600),
    )
}

async fn register_test_service(mgr: &DistributedSessionManager) {
    let cred = ServiceCredential {
        service_id: "svc-a".to_string(),
        service_name: "Service A".to_string(),
        secret_key: "secret_a".to_string(),
        created_at: Utc::now(),
        permissions: vec!["read".to_string(), "write".to_string()],
    };
    mgr.register_service(cred).await.unwrap();
}

// ── Success cases: service auth ────────────────────────────────────────────

#[tokio::test]
async fn test_verify_service_valid_credentials() {
    let mgr = test_manager();
    register_test_service(&mgr).await;
    let cred = mgr
        .verify_service("svc-a", "secret_a")
        .await
        .expect("verify");
    assert_eq!(cred.service_name, "Service A");
}

#[tokio::test]
async fn test_verify_service_wrong_secret() {
    let mgr = test_manager();
    register_test_service(&mgr).await;
    let result = mgr.verify_service("svc-a", "wrong_secret").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::PermissionDenied
    ));
}

#[tokio::test]
async fn test_verify_unregistered_service() {
    let mgr = test_manager();
    let result = mgr.verify_service("unknown", "secret").await;
    assert!(result.is_err());
}

// ── Success cases: session CRUD ────────────────────────────────────────────

#[tokio::test]
async fn test_create_and_get_session() {
    let mgr = test_manager();
    let session = mgr
        .create_session("user_1".into(), "token_1".into())
        .await
        .expect("create");
    assert!(!session.session_id.is_empty());
    assert_eq!(session.login_id, "user_1");
    assert_eq!(session.token, "token_1");

    let retrieved = mgr.get_session(&session.session_id).await.expect("get");
    assert_eq!(retrieved.login_id, "user_1");
}

#[tokio::test]
async fn test_session_has_unique_ids() {
    let mgr = test_manager();
    let s1 = mgr
        .create_session("user_1".into(), "tok1".into())
        .await
        .expect("s1");
    let s2 = mgr
        .create_session("user_2".into(), "tok2".into())
        .await
        .expect("s2");
    assert_ne!(s1.session_id, s2.session_id);
}

#[tokio::test]
async fn test_delete_session() {
    let mgr = test_manager();
    let session = mgr
        .create_session("user_del".into(), "tok_del".into())
        .await
        .expect("create");
    mgr.delete_session(&session.session_id)
        .await
        .expect("delete");
    let result = mgr.get_session(&session.session_id).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SaTokenError::SessionNotFound));
}

#[tokio::test]
async fn test_refresh_session_extends_timeout() {
    let mgr = test_manager();
    let session = mgr
        .create_session("user_ref".into(), "tok_ref".into())
        .await
        .expect("create");
    let created = session.create_time;
    mgr.refresh_session(&session.session_id)
        .await
        .expect("refresh");
    let refreshed = mgr.get_session(&session.session_id).await.expect("get");
    // After refresh, last_active_time should be updated
    assert!(refreshed.last_access >= created);
}

// ── Success cases: attributes ──────────────────────────────────────────────

#[tokio::test]
async fn test_set_and_get_attribute() {
    let mgr = test_manager();
    let session = mgr
        .create_session("user_attr".into(), "tok_attr".into())
        .await
        .expect("create");
    mgr.set_attribute(&session.session_id, "role".to_string(), "admin".to_string())
        .await
        .expect("set");
    let val = mgr
        .get_attribute(&session.session_id, "role")
        .await
        .expect("get role");
    assert_eq!(val, Some("admin".to_string()));
}

#[tokio::test]
async fn test_remove_attribute() {
    let mgr = test_manager();
    let session = mgr
        .create_session("user_rm_attr".into(), "tok_rm".into())
        .await
        .expect("create");
    mgr.set_attribute(&session.session_id, "temp".to_string(), "value".to_string())
        .await
        .expect("set");
    mgr.remove_attribute(&session.session_id, "temp")
        .await
        .expect("remove");
    let val = mgr
        .get_attribute(&session.session_id, "temp")
        .await
        .expect("get");
    assert_eq!(val, None);
}

#[tokio::test]
async fn test_get_nonexistent_attribute_returns_none() {
    let mgr = test_manager();
    let session = mgr
        .create_session("user_noattr".into(), "tok_na".into())
        .await
        .expect("create");
    let val = mgr
        .get_attribute(&session.session_id, "no_such_key")
        .await
        .expect("get");
    assert_eq!(val, None);
}

// ── Success cases: multi-session ───────────────────────────────────────────

#[tokio::test]
async fn test_get_sessions_by_login_id() {
    let mgr = test_manager();
    mgr.create_session("user_multi".into(), "tok_a".into())
        .await
        .expect("s1");
    mgr.create_session("user_multi".into(), "tok_b".into())
        .await
        .expect("s2");
    let sessions = mgr
        .get_sessions_by_login_id("user_multi")
        .await
        .expect("get all");
    assert_eq!(sessions.len(), 2);
}

#[tokio::test]
async fn test_delete_all_sessions() {
    let mgr = test_manager();
    let s1 = mgr
        .create_session("user_del_all".into(), "tok1".into())
        .await
        .expect("s1");
    mgr.create_session("user_del_all".into(), "tok2".into())
        .await
        .expect("s2");
    mgr.delete_all_sessions("user_del_all")
        .await
        .expect("delete all");
    let result = mgr.get_session(&s1.session_id).await;
    assert!(result.is_err());
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_nonexistent_session() {
    let mgr = test_manager();
    let result = mgr.get_session("no_such_session_id").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SaTokenError::SessionNotFound));
}

#[tokio::test]
async fn test_delete_nonexistent_session_is_noop() {
    let mgr = test_manager();
    // Deleting a nonexistent session is a no-op (should not error)
    let result = mgr.delete_session("no_such_session").await;
    assert!(
        result.is_ok(),
        "delete nonexistent session should be ok (noop)"
    );
}

#[tokio::test]
async fn test_update_nonexistent_session_is_noop() {
    let mgr = test_manager();
    let fake = DistributedSession {
        session_id: "fake_id".to_string(),
        login_id: "fake_user".to_string(),
        token: "fake_token".to_string(),
        service_id: "test-service".to_string(),
        create_time: Utc::now(),
        last_access: Utc::now(),
        attributes: HashMap::new(),
    };
    // Updating a nonexistent session is a no-op
    let result = mgr.update_session(fake).await;
    assert!(
        result.is_ok(),
        "update nonexistent session should be ok (noop)"
    );
}
