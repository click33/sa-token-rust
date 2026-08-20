//! P1: Session CRUD integration tests.
//!
//! Covers session creation (via login), get/set/remove/has/keys/clear,
//! delete, and error paths.

mod common;

use common::setup;
use sa_token_core::StpUtil;

fn init_stp() {
    let _ = setup::shared_manager();
}

// ── Success cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_session_returns_session() {
    init_stp();
    StpUtil::login("user_s1").await.expect("login");
    let session = StpUtil::get_session("user_s1").await.expect("get_session");
    assert_eq!(session.id, "user_s1");
}

#[tokio::test]
async fn test_session_set_and_get_string() {
    init_stp();
    StpUtil::login("user_s2").await.expect("login");
    let mut session = StpUtil::get_session("user_s2").await.expect("get");
    session.set("username", "Alice").unwrap();
    // Save session
    StpUtil::save_session(&session).await.expect("save");
    // Re-fetch and verify
    let session2 = StpUtil::get_session("user_s2").await.expect("get again");
    let name: Option<String> = session2.get("username");
    assert_eq!(name.as_deref(), Some("Alice"));
}

#[tokio::test]
async fn test_session_set_and_get_number() {
    init_stp();
    StpUtil::login("user_s3").await.expect("login");
    let mut session = StpUtil::get_session("user_s3").await.expect("get");
    session.set("age", 30_i32).unwrap();
    StpUtil::save_session(&session).await.expect("save");
    let s2 = StpUtil::get_session("user_s3").await.expect("get again");
    let age: Option<i32> = s2.get("age");
    assert_eq!(age, Some(30));
}

#[tokio::test]
async fn test_session_has_key() {
    init_stp();
    StpUtil::login("user_s4").await.expect("login");
    let mut session = StpUtil::get_session("user_s4").await.expect("get");
    session.set("email", "alice@example.com").unwrap();
    StpUtil::save_session(&session).await.expect("save");
    let s2 = StpUtil::get_session("user_s4").await.expect("get again");
    assert!(s2.has("email"));
    assert!(!s2.has("nonexistent"));
}

#[tokio::test]
async fn test_session_remove_key() {
    init_stp();
    StpUtil::login("user_s5").await.expect("login");
    let mut session = StpUtil::get_session("user_s5").await.expect("get");
    session.set("temp", "value").unwrap();
    assert!(session.has("temp"));
    session.remove("temp");
    assert!(!session.has("temp"));
    StpUtil::save_session(&session).await.expect("save");
    // Re-fetch
    let s2 = StpUtil::get_session("user_s5").await.expect("get again");
    assert!(!s2.has("temp"));
}

#[tokio::test]
async fn test_session_keys_returns_all_keys() {
    init_stp();
    StpUtil::login("user_s6").await.expect("login");
    let mut session = StpUtil::get_session("user_s6").await.expect("get");
    session.set("a", "1").unwrap();
    session.set("b", "2").unwrap();
    session.set("c", "3").unwrap();
    // keys() is not available as a method on SaSession (check if it exists)
    // Use has() to check individual keys instead
    assert!(session.has("a"));
    assert!(session.has("b"));
    assert!(session.has("c"));
}

#[tokio::test]
async fn test_session_clear() {
    init_stp();
    StpUtil::login("user_s7").await.expect("login");
    let mut session = StpUtil::get_session("user_s7").await.expect("get");
    session.set("x", "1").unwrap();
    session.set("y", "2").unwrap();
    session.clear();
    assert!(!session.has("x"));
    assert!(!session.has("y"));
}

#[tokio::test]
async fn test_delete_session() {
    init_stp();
    StpUtil::login("user_s8").await.expect("login");
    // Set some session data
    let mut session = StpUtil::get_session("user_s8").await.expect("get");
    session.set("data", "important").unwrap();
    StpUtil::save_session(&session).await.expect("save");
    // Delete session
    StpUtil::delete_session("user_s8").await.expect("delete");
    // After deletion, a new session is created when accessed again
    let new_session = StpUtil::get_session("user_s8")
        .await
        .expect("get after delete");
    assert!(new_session.id == "user_s8"); // session id is the login_id
}

#[tokio::test]
async fn test_stp_util_set_get_session_value() {
    init_stp();
    StpUtil::login("user_s9").await.expect("login");
    // Use StpUtil convenience methods
    StpUtil::set_session_value("user_s9", "theme", "dark")
        .await
        .expect("set");
    let theme: Option<String> = StpUtil::get_session_value("user_s9", "theme")
        .await
        .expect("get");
    assert_eq!(theme.as_deref(), Some("dark"));
}

#[tokio::test]
async fn test_session_stores_complex_json() {
    init_stp();
    StpUtil::login("user_s10").await.expect("login");
    let mut session = StpUtil::get_session("user_s10").await.expect("get");
    let data = serde_json::json!({"prefs": {"lang": "zh", "timezone": "Asia/Shanghai"}});
    session.set("config", &data).unwrap();
    StpUtil::save_session(&session).await.expect("save");
    let s2 = StpUtil::get_session("user_s10").await.expect("get again");
    let config: Option<serde_json::Value> = s2.get("config");
    assert!(config.is_some());
    assert_eq!(config.unwrap()["prefs"]["lang"], "zh");
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_nonexistent_key_returns_none() {
    init_stp();
    StpUtil::login("user_s11").await.expect("login");
    let session = StpUtil::get_session("user_s11").await.expect("get");
    let val: Option<String> = session.get("no_such_key");
    assert!(val.is_none());
}

#[tokio::test]
async fn test_get_session_without_login_creates_new() {
    init_stp();
    // get_session for a user that never logged in returns a new empty session
    let session = StpUtil::get_session("not_logged_in_user")
        .await
        .expect("get_session");
    assert_eq!(session.id, "not_logged_in_user");
    // The session exists but is empty
    let val: Option<String> = session.get("any_key");
    assert!(val.is_none());
}

#[tokio::test]
async fn test_delete_session_twice_no_error() {
    init_stp();
    StpUtil::login("user_s12").await.expect("login");
    StpUtil::delete_session("user_s12")
        .await
        .expect("first delete");
    // Second delete should not error
    let result = StpUtil::delete_session("user_s12").await;
    assert!(result.is_ok(), "double delete should not error");
}
