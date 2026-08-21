//! 临时 Token 集成测试。

mod common;

use common::setup;
use sa_token_core::temp_token::TempTokenManager;
use sa_token_core::SaTokenError;

#[tokio::test]
async fn test_temp_token_create_parse_delete() {
    let mgr = setup::fresh_manager();
    let temp = TempTokenManager::new(mgr.dao().clone());
    let token = temp
        .create("ns", serde_json::json!("payload"), 120, true)
        .await
        .expect("create");
    let rec = temp.parse("ns", &token).await.expect("parse");
    assert_eq!(rec.value, serde_json::json!("payload"));
    assert_eq!(
        temp.find_token("ns", "payload").await.expect("index"),
        token
    );
    temp.delete("ns", &token).await.expect("delete");
    assert!(matches!(
        temp.parse("ns", &token).await,
        Err(SaTokenError::TempTokenNotFound)
    ));
}

#[tokio::test]
async fn test_temp_token_timeout_zero_errors() {
    let mgr = setup::fresh_manager();
    let temp = TempTokenManager::new(mgr.dao().clone());
    let err = temp
        .create("ns", serde_json::json!(1), 0, false)
        .await
        .expect_err("timeout=0 must fail");
    assert!(matches!(err, SaTokenError::ConfigError(_)));
}

#[tokio::test]
async fn test_temp_token_expired_via_clock() {
    let mgr = setup::fresh_manager();
    let temp = TempTokenManager::new(mgr.dao().clone());
    let token = temp
        .create("ns", serde_json::json!("x"), 3600, false)
        .await
        .expect("create");
    // 灰盒：把 expire_at 拨到过去
    let key = mgr.keys().temp_token("ns", &token);
    let mut rec: sa_token_core::temp_token::TempTokenRecord =
        mgr.dao().get_object(&key).await.expect("get").expect("some");
    rec.expire_at = Some(chrono::Utc::now() - chrono::Duration::seconds(5));
    mgr.dao()
        .set_object(&key, &rec, None)
        .await
        .expect("set");
    assert!(matches!(
        temp.parse("ns", &token).await,
        Err(SaTokenError::TempTokenExpired)
    ));
}
