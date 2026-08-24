//! P1: Session CRUD integration tests.

mod common;

use common::setup;
use sa_token_core::StpUtil;
use serial_test::serial;

fn init_stp() {
    let _mgr = setup::shared_manager();
}

#[tokio::test]
#[serial]
async fn test_get_session_returns_session() {
    init_stp();
    let id = setup::unique_login_id("s1");
    StpUtil::login(&id).await.expect("login");
    let session = StpUtil::get_session(&id).await.expect("get_session");
    assert_eq!(session.id, id);
}

#[tokio::test]
#[serial]
async fn test_session_set_and_get_string() {
    init_stp();
    let id = setup::unique_login_id("s2");
    StpUtil::login(&id).await.expect("login");
    let mut session = StpUtil::get_session(&id).await.expect("get");
    session.set("username", "Alice").expect("set");
    StpUtil::save_session(&session).await.expect("save");
    let session2 = StpUtil::get_session(&id).await.expect("get again");
    let name: Option<String> = session2.get("username");
    assert_eq!(name.as_deref(), Some("Alice"));
}

#[tokio::test]
#[serial]
async fn test_session_set_and_get_number() {
    init_stp();
    let id = setup::unique_login_id("s3");
    StpUtil::login(&id).await.expect("login");
    let mut session = StpUtil::get_session(&id).await.expect("get");
    session.set("age", 30_i32).expect("set");
    StpUtil::save_session(&session).await.expect("save");
    let s2 = StpUtil::get_session(&id).await.expect("get again");
    assert_eq!(s2.get::<i32>("age"), Some(30));
}

#[tokio::test]
#[serial]
async fn test_session_has_and_remove() {
    init_stp();
    let id = setup::unique_login_id("s4");
    StpUtil::login(&id).await.expect("login");
    let mut session = StpUtil::get_session(&id).await.expect("get");
    session.set("email", "alice@example.com").expect("set");
    StpUtil::save_session(&session).await.expect("save");
    let mut s2 = StpUtil::get_session(&id).await.expect("get");
    assert!(s2.has("email"));
    assert!(!s2.has("nonexistent"));
    s2.remove("email");
    StpUtil::save_session(&s2).await.expect("save");
    let s3 = StpUtil::get_session(&id).await.expect("get");
    assert!(!s3.has("email"));
}

#[tokio::test]
#[serial]
async fn test_session_keys_returns_all_keys() {
    init_stp();
    let id = setup::unique_login_id("s6");
    StpUtil::login(&id).await.expect("login");
    let mut session = StpUtil::get_session(&id).await.expect("get");
    session.set("a", "1").expect("a");
    session.set("b", "2").expect("b");
    session.set("c", "3").expect("c");
    StpUtil::save_session(&session).await.expect("save");
    let s2 = StpUtil::get_session(&id).await.expect("reload");
    let keys = s2.keys();
    assert!(keys.iter().any(|k| k == "a"));
    assert!(keys.iter().any(|k| k == "b"));
    assert!(keys.iter().any(|k| k == "c"));
}

#[tokio::test]
#[serial]
async fn test_session_clear_persisted() {
    init_stp();
    let id = setup::unique_login_id("s7");
    StpUtil::login(&id).await.expect("login");
    let mut session = StpUtil::get_session(&id).await.expect("get");
    session.set("x", "1").expect("x");
    session.set("y", "2").expect("y");
    session.clear();
    StpUtil::save_session(&session).await.expect("save");
    let s2 = StpUtil::get_session(&id).await.expect("reload");
    assert!(!s2.has("x"));
    assert!(!s2.has("y"));
}

#[tokio::test]
#[serial]
async fn test_delete_session_drops_saved_keys() {
    init_stp();
    let id = setup::unique_login_id("s_del");
    StpUtil::login(&id).await.expect("login");
    StpUtil::set_session_value(&id, "data", "important")
        .await
        .expect("set");
    StpUtil::delete_session(&id).await.expect("delete");
    let v: Option<String> = StpUtil::get_session_value(&id, "data")
        .await
        .expect("get after delete");
    assert_eq!(v, None, "deleted session must not keep previous keys");
}

#[tokio::test]
#[serial]
async fn test_stp_util_set_get_session_value() {
    init_stp();
    let id = setup::unique_login_id("s9");
    StpUtil::login(&id).await.expect("login");
    StpUtil::set_session_value(&id, "theme", "dark")
        .await
        .expect("set");
    let theme: Option<String> = StpUtil::get_session_value(&id, "theme").await.expect("get");
    assert_eq!(theme.as_deref(), Some("dark"));
}

#[tokio::test]
#[serial]
async fn test_session_stores_complex_json() {
    init_stp();
    let id = setup::unique_login_id("s10");
    StpUtil::login(&id).await.expect("login");
    let mut session = StpUtil::get_session(&id).await.expect("get");
    let data = serde_json::json!({"prefs": {"lang": "zh", "timezone": "Asia/Shanghai"}});
    session.set("config", &data).expect("set");
    StpUtil::save_session(&session).await.expect("save");
    let s2 = StpUtil::get_session(&id).await.expect("get");
    let config: Option<serde_json::Value> = s2.get("config");
    assert_eq!(config.expect("config")["prefs"]["lang"], "zh");
}

#[tokio::test]
#[serial]
async fn test_get_nonexistent_key_returns_none() {
    init_stp();
    let id = setup::unique_login_id("s11");
    StpUtil::login(&id).await.expect("login");
    let session = StpUtil::get_session(&id).await.expect("get");
    let val: Option<String> = session.get("no_such_key");
    assert!(val.is_none());
}

#[tokio::test]
#[serial]
async fn test_delete_session_twice_no_error() {
    init_stp();
    let id = setup::unique_login_id("s12");
    StpUtil::login(&id).await.expect("login");
    StpUtil::delete_session(&id).await.expect("first");
    StpUtil::delete_session(&id)
        .await
        .expect("double delete should not error");
}
