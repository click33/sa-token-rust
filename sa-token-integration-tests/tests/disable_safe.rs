//! Phase3: disable / safe API integration tests

mod common;

use common::setup;
use sa_token_core::{SaTokenConfig, SaTokenError, SaTokenManager};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

fn manager() -> Arc<SaTokenManager> {
    let storage = Arc::new(MemoryStorage::new());
    let config = SaTokenConfig::builder().timeout(3600).build_config();
    Arc::new(SaTokenManager::new(storage, config))
}

#[tokio::test]
async fn disable_blocks_login_and_check_disable() {
    let mgr = manager();
    let id = setup::unique_login_id("banned");
    mgr.disable_level(&id, "login", 2, 120)
        .await
        .expect("disable");
    setup::assert_err(mgr.check_disable_level(&id, "login", 1).await, "banned");
    // 封禁后 login 必须失败
    let login = mgr.login(&id).await;
    setup::assert_err(login, "banned");
}

#[tokio::test]
async fn untie_disable_allows_login_again() {
    let mgr = manager();
    let id = setup::unique_login_id("untie");
    mgr.disable(&id, 60).await.expect("disable");
    assert!(mgr.is_disable_level(&id, "login", 1).await.expect("is"));
    mgr.untie_disable(&id, "login").await.expect("untie");
    assert!(
        !mgr.is_disable_level(&id, "login", 1)
            .await
            .expect("cleared")
    );
    let token = mgr.login(&id).await.expect("login after untie");
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn safe_open_check_close_cycle() {
    let mgr = manager();
    let token = mgr.login("u_safe").await.expect("login");
    // 未 open：check_safe 必须失败
    let before = mgr.check_safe(&token, "").await;
    assert!(
        matches!(before, Err(SaTokenError::NotSafe(_))),
        "got {before:?}"
    );
    mgr.open_safe(&token, "", 120).await.expect("open");
    mgr.check_safe(&token, "").await.expect("check after open");
    mgr.close_safe(&token, "").await.expect("close");
    let after = mgr.check_safe(&token, "").await;
    assert!(matches!(after, Err(SaTokenError::NotSafe(_))));
}

#[tokio::test]
async fn safe_service_isolation() {
    let mgr = manager();
    let token = mgr.login("u_safe2").await.expect("login");
    mgr.open_safe(&token, "pay", 120).await.expect("open pay");
    mgr.check_safe(&token, "pay").await.expect("pay ok");
    let other = mgr.check_safe(&token, "transfer").await;
    assert!(
        matches!(other, Err(SaTokenError::NotSafe(_))),
        "different service must not inherit safe"
    );
}
