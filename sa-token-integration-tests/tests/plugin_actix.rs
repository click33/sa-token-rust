//! P2: Actix-web framework plugin integration tests.
//!
//! Tests SaTokenLayer middleware, LoginIdExtractor, OptionalSaTokenExtractor,
//! and context injection into actix_web request extensions.

mod common;

use actix_web::{App, HttpResponse, test, web};
use std::sync::Arc;

use sa_token_core::{SaTokenConfig, StpUtil, config::TokenStyle};
use sa_token_plugin_actix_web_v4::{
    LoginIdExtractor, OptionalSaTokenExtractor, SaTokenLayer, SaTokenState as ActixState,
};
use sa_token_storage_memory::MemoryStorage;

static MANAGER: std::sync::OnceLock<Arc<sa_token_core::SaTokenManager>> =
    std::sync::OnceLock::new();

fn init_manager() -> Arc<sa_token_core::SaTokenManager> {
    MANAGER
        .get_or_init(|| {
            let storage = Arc::new(MemoryStorage::new());
            let config = SaTokenConfig::builder()
                .token_name("sa-token")
                .timeout(3600)
                .token_style(TokenStyle::Uuid)
                .build_config();
            let manager = sa_token_core::SaTokenManager::new(storage, config);
            let _ = StpUtil::try_init_manager(manager.clone());
            Arc::new(manager)
        })
        .clone()
}

fn test_state() -> ActixState {
    ActixState {
        manager: init_manager(),
    }
}

// ── Success cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_sa_token_layer_injects_login_id() {
    let mgr = init_manager();
    let state = test_state();
    let token = mgr.login("actix_user").await.expect("login");

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state.clone())).route(
        "/me",
        web::get().to(|ext: LoginIdExtractor| async move { HttpResponse::Ok().body(ext.0) }),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/me")
        .insert_header(("sa-token", token.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    assert_eq!(body.as_ref(), b"actix_user");
}

#[tokio::test]
async fn test_optional_extractor_returns_none_without_token() {
    init_manager();
    let state = test_state();

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state.clone())).route(
        "/pub",
        web::get().to(|ext: OptionalSaTokenExtractor| async move {
            match ext.0 {
                Some(t) => HttpResponse::Ok().body(t.to_string()),
                None => HttpResponse::Ok().body("no_token"),
            }
        }),
    ))
    .await;

    let req = test::TestRequest::get().uri("/pub").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    assert_eq!(body.as_ref(), b"no_token");
}

#[tokio::test]
async fn test_optional_extractor_returns_token_when_present() {
    let mgr = init_manager();
    let state = test_state();
    let token = mgr.login("actix_opt").await.expect("login");

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state.clone())).route(
        "/me",
        web::get().to(|ext: OptionalSaTokenExtractor| async move {
            HttpResponse::Ok().body(ext.0.map(|t| t.to_string()).unwrap_or_default())
        }),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/me")
        .insert_header(("sa-token", token.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    assert!(
        !body.as_ref().is_empty(),
        "body should contain the token value"
    );
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_login_id_extractor_returns_401_without_token() {
    let state = test_state();

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state.clone())).route(
        "/protected",
        web::get().to(|_ext: LoginIdExtractor| async move { HttpResponse::Ok().body("ok") }),
    ))
    .await;

    let req = test::TestRequest::get().uri("/protected").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_login_id_extractor_returns_401_with_expired_token() {
    let storage = Arc::new(MemoryStorage::new());
    let config = SaTokenConfig::builder()
        .token_name("sa-token")
        .timeout(1)
        .build_config();
    let manager = sa_token_core::SaTokenManager::new(storage, config);
    let state = ActixState {
        manager: manager.clone().into(),
    };
    let token = manager.login("actix_exp").await.expect("login");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state.clone())).route(
        "/me",
        web::get().to(|ext: LoginIdExtractor| async move { HttpResponse::Ok().body(ext.0) }),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/me")
        .insert_header(("sa-token", token.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}
