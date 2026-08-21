//! Online presence 经 login / kick 链路。

mod common;

use common::setup;
use sa_token_core::online::{InMemoryPusher, OnlineManager};
use sa_token_core::SaTokenManager;
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[tokio::test]
async fn test_login_marks_online_kick_marks_offline() {
    let storage = Arc::new(MemoryStorage::new());
    let pusher = Arc::new(InMemoryPusher::new());
    let online_mgr = Arc::new(OnlineManager::new());
    online_mgr.register_pusher(pusher.clone()).await;
    let mgr =
        SaTokenManager::new(storage, setup::default_config()).with_online_manager(online_mgr.clone());

    let token = mgr.login("online_user").await.expect("login");
    assert!(
        online_mgr.is_online("online_user").await.expect("is_online"),
        "login must mark_online"
    );
    let sessions = online_mgr
        .get_user_sessions("online_user")
        .await
        .expect("sessions");
    assert!(sessions.iter().any(|s| s.token == token.as_str()));

    mgr.kick_out("default", "online_user")
        .await
        .expect("kick");
    assert!(
        !online_mgr
            .is_online("online_user")
            .await
            .expect("after kick"),
        "kick must clear online presence"
    );
    let msgs = pusher.get_messages("online_user").await;
    assert!(
        !msgs.is_empty(),
        "kick_out_notify must push at least one message"
    );
}
