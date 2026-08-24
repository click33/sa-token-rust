//! 经 Manager.login / logout / kick 触发的事件监听。

mod common;

use async_trait::async_trait;
use common::setup;
use sa_token_core::{SaTokenListener, SaTokenManager};
use sa_token_storage_memory::MemoryStorage;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct CountingListener {
    logins: AtomicUsize,
    logouts: AtomicUsize,
    kicks: AtomicUsize,
}

#[async_trait]
impl SaTokenListener for CountingListener {
    async fn on_login(&self, _login_id: &str, _token: &str, _login_type: &str) {
        self.logins.fetch_add(1, Ordering::SeqCst);
    }
    async fn on_logout(&self, _login_id: &str, _token: &str, _login_type: &str) {
        self.logouts.fetch_add(1, Ordering::SeqCst);
    }
    async fn on_kick_out(&self, _login_id: &str, _token: &str, _login_type: &str) {
        self.kicks.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn test_login_logout_kick_fire_listeners() {
    let listener = Arc::new(CountingListener {
        logins: AtomicUsize::new(0),
        logouts: AtomicUsize::new(0),
        kicks: AtomicUsize::new(0),
    });
    let storage = Arc::new(MemoryStorage::new());
    let mgr = SaTokenManager::new(storage, setup::default_config());
    mgr.event_bus().register(listener.clone());

    let token = mgr.login("evt_user").await.expect("login");
    assert_eq!(listener.logins.load(Ordering::SeqCst), 1);

    mgr.logout(&token).await.expect("logout");
    assert_eq!(listener.logouts.load(Ordering::SeqCst), 1);

    let token2 = mgr.login("evt_user").await.expect("login2");
    mgr.kick_out("default", "evt_user").await.expect("kick");
    assert!(
        listener.kicks.load(Ordering::SeqCst) >= 1,
        "kick must fire on_kick_out"
    );
    let _ = token2;
}
