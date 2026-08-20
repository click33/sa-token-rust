//! P3: Online user management integration tests.
//!
//! Tests OnlineManager: mark_online/offline, is_online, online count,
//! push messages, and kick_out_notify.

mod common;

use chrono::Utc;
use sa_token_core::{InMemoryPusher, MessageType, OnlineManager, OnlineUser, PushMessage};
use std::collections::HashMap;
use std::sync::Arc;

fn test_user(login_id: &str, token: &str, device: &str) -> OnlineUser {
    OnlineUser {
        login_type: "login".to_string(),
        login_id: login_id.to_string(),
        token: token.to_string(),
        device: device.to_string(),
        connect_time: Utc::now(),
        last_activity: Utc::now(),
        metadata: HashMap::new(),
    }
}

// ── Success cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_mark_online_and_is_online() {
    let mgr = OnlineManager::new();
    assert!(!mgr.is_online("user_a").await.unwrap());
    mgr.mark_online(test_user("user_a", "tok1", "web"))
        .await
        .unwrap();
    assert!(mgr.is_online("user_a").await.unwrap());
}

#[tokio::test]
async fn test_get_online_count() {
    let mgr = OnlineManager::new();
    assert_eq!(mgr.get_online_count().await.unwrap(), 0);
    mgr.mark_online(test_user("user_a", "tok1", "web"))
        .await
        .unwrap();
    mgr.mark_online(test_user("user_b", "tok2", "mobile"))
        .await
        .unwrap();
    assert_eq!(mgr.get_online_count().await.unwrap(), 2);
}

#[tokio::test]
async fn test_get_online_users_returns_login_ids() {
    let mgr = OnlineManager::new();
    mgr.mark_online(test_user("user_a", "tok1", "web"))
        .await
        .unwrap();
    mgr.mark_online(test_user("user_b", "tok2", "mobile"))
        .await
        .unwrap();
    let users = mgr.get_online_users().await.unwrap();
    assert!(users.contains(&"user_a".to_string()));
    assert!(users.contains(&"user_b".to_string()));
}

#[tokio::test]
async fn test_mark_offline_removes_user() {
    let mgr = OnlineManager::new();
    mgr.mark_online(test_user("user_a", "tok1", "web"))
        .await
        .unwrap();
    assert!(mgr.is_online("user_a").await.unwrap());
    mgr.mark_offline("user_a", "tok1").await.unwrap();
    assert!(!mgr.is_online("user_a").await.unwrap());
}

#[tokio::test]
async fn test_mark_offline_all_removes_all_sessions() {
    let mgr = OnlineManager::new();
    mgr.mark_online(test_user("user_a", "tok_web", "web"))
        .await
        .unwrap();
    mgr.mark_online(test_user("user_a", "tok_mobile", "mobile"))
        .await
        .unwrap();
    assert_eq!(mgr.get_online_count().await.unwrap(), 1); // same login_id, 2 devices
    mgr.mark_offline_all("user_a").await.unwrap();
    assert!(!mgr.is_online("user_a").await.unwrap());
    assert_eq!(mgr.get_online_count().await.unwrap(), 0);
}

#[tokio::test]
async fn test_mark_offline_one_device_keeps_other() {
    let mgr = OnlineManager::new();
    mgr.mark_online(test_user("user_a", "tok_web", "web"))
        .await
        .unwrap();
    mgr.mark_online(test_user("user_a", "tok_mobile", "mobile"))
        .await
        .unwrap();
    mgr.mark_offline("user_a", "tok_web").await.unwrap();
    // User should still be online (mobile session remains)
    assert!(mgr.is_online("user_a").await.unwrap());
    assert_eq!(mgr.get_online_count().await.unwrap(), 1);
}

#[tokio::test]
async fn test_push_to_user_with_in_memory_pusher() {
    let mgr = OnlineManager::new();
    let pusher = Arc::new(InMemoryPusher::new());
    mgr.register_pusher(pusher.clone()).await;
    mgr.mark_online(test_user("user_a", "tok1", "web"))
        .await
        .unwrap();

    mgr.push_to_user("user_a", "Hello!".to_string())
        .await
        .expect("push");
    let messages = pusher.get_messages("user_a").await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].content, "Hello!");
}

#[tokio::test]
async fn test_push_message_to_user_with_structured_message() {
    let mgr = OnlineManager::new();
    let pusher = Arc::new(InMemoryPusher::new());
    mgr.register_pusher(pusher.clone()).await;
    mgr.mark_online(test_user("user_b", "tok2", "mobile"))
        .await
        .unwrap();

    let msg = PushMessage {
        message_id: "msg_001".to_string(),
        content: "System notification".to_string(),
        message_type: MessageType::Notification,
        timestamp: Utc::now(),
        metadata: HashMap::new(),
    };
    mgr.push_message_to_user("user_b", msg)
        .await
        .expect("push message");
    let msgs = pusher.get_messages("user_b").await;
    assert_eq!(msgs.len(), 1);
    assert!(matches!(msgs[0].message_type, MessageType::Notification));
}

#[tokio::test]
async fn test_broadcast_sends_to_all() {
    let mgr = OnlineManager::new();
    let pusher = Arc::new(InMemoryPusher::new());
    mgr.register_pusher(pusher.clone()).await;
    mgr.mark_online(test_user("user_a", "tok1", "web"))
        .await
        .unwrap();
    mgr.mark_online(test_user("user_b", "tok2", "mobile"))
        .await
        .unwrap();

    mgr.broadcast("announcement".to_string())
        .await
        .expect("broadcast");
    assert_eq!(pusher.get_messages("user_a").await.len(), 1);
    assert_eq!(pusher.get_messages("user_b").await.len(), 1);
}

#[tokio::test]
async fn test_get_user_sessions_returns_all_devices() {
    let mgr = OnlineManager::new();
    mgr.mark_online(test_user("user_a", "tok_web", "web"))
        .await
        .unwrap();
    mgr.mark_online(test_user("user_a", "tok_mobile", "mobile"))
        .await
        .unwrap();
    let sessions = mgr.get_user_sessions("user_a").await.unwrap();
    assert_eq!(sessions.len(), 2);
}

// ── Edge cases ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_push_to_user_with_no_pushers_is_ok() {
    let mgr = OnlineManager::new();
    // push_to_user dispatches to registered pushers. With no pushers, it's Ok.
    let result = mgr.push_to_user("nobody", "hello".to_string()).await;
    assert!(result.is_ok(), "push with no pushers should be ok (noop)");
}

#[tokio::test]
async fn test_clear_messages() {
    let mgr = OnlineManager::new();
    let pusher = Arc::new(InMemoryPusher::new());
    mgr.register_pusher(pusher.clone()).await;
    mgr.mark_online(test_user("user_c", "tok3", "web"))
        .await
        .unwrap();
    mgr.push_to_user("user_c", "msg1".to_string())
        .await
        .expect("push1");
    mgr.push_to_user("user_c", "msg2".to_string())
        .await
        .expect("push2");
    assert_eq!(pusher.get_messages("user_c").await.len(), 2);
    pusher.clear_messages("user_c").await;
    assert_eq!(pusher.get_messages("user_c").await.len(), 0);
}
