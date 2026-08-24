//! `SaTokenContext` task-local 与兼容路径行为。
use std::sync::Arc;

use sa_token_core::SaTokenContext;
use sa_token_core::SaTokenManager;
use sa_token_core::config::SaTokenConfig;
use sa_token_storage_memory::MemoryStorage;

fn build_manager() -> SaTokenManager {
    let storage = Arc::new(MemoryStorage::new());
    SaTokenConfig::builder().storage(storage).build()
}

/// A. scope 内跨 await 跨 worker 仍能拿到 ctx
#[test]
fn ctx_survives_yield_and_thread_hop() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let manager = build_manager();
        let token = manager.login("u-1".to_string()).await.unwrap();
        let info = manager.get_token_info(&token).await.unwrap();

        let ctx = SaTokenContext::builder()
            .token(token.clone())
            .login_id(info.login_id.as_ref())
            .token_info(Arc::new(info))
            .build();

        let got: Option<String> = SaTokenContext::scope(ctx, async {
            for _ in 0..32 {
                tokio::task::yield_now().await;
            }
            SaTokenContext::try_current().and_then(|c| c.login_id())
        })
        .await;

        assert_eq!(got.as_deref(), Some("u-1"));
    });
}

/// B. 不在 scope 内：try_current 应为 None
#[test]
fn ctx_is_none_outside_scope() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        assert!(SaTokenContext::try_current().is_none());
    });
}

/// C. 老 set_current 同线程同步仍可读（兼容路径）
#[test]
fn legacy_thread_local_still_works_same_thread() {
    let ctx = SaTokenContext::builder().login_id("legacy").build();
    SaTokenContext::set_current(ctx);
    assert_eq!(
        SaTokenContext::try_current().unwrap().login_id().as_deref(),
        Some("legacy")
    );
    SaTokenContext::clear();
    assert!(SaTokenContext::try_current().is_none());
}
