//! Actix-web 插件：真实 Header / Cookie / Bearer 注入、Extractor 401、path_auth。
//!
//! 过期用灰盒拨钟，禁止 sleep。

mod common;

use actix_web::{App, HttpResponse, dev::Service, test, web};
use common::setup;
use sa_token_core::{StpUtil, router::PathAuthConfig};
use sa_token_plugin_actix_web_v4::{
    LoginIdExtractor, OptionalSaTokenExtractor, SaTokenLayer, SaTokenMiddleware,
    SaTokenState as ActixState,
};

fn test_state() -> ActixState {
    let _ = setup::shared_manager();
    ActixState {
        manager: setup::shared_manager(),
    }
}

// ── 成功路径 ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_sa_token_layer_injects_login_id_from_header() {
    let mgr = setup::shared_manager();
    let state = test_state();
    let id = setup::unique_login_id("actix_hdr");
    let token = mgr.login(&id).await.expect("login");

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state)).route(
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
    assert_eq!(body.as_ref(), id.as_bytes());
}

#[tokio::test]
async fn test_sa_token_layer_injects_login_id_from_cookie() {
    let mgr = setup::shared_manager();
    let state = test_state();
    let id = setup::unique_login_id("actix_cookie");
    let token = mgr.login(&id).await.expect("login");

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state)).route(
        "/me",
        web::get().to(|ext: LoginIdExtractor| async move { HttpResponse::Ok().body(ext.0) }),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/me")
        .insert_header(("cookie", format!("sa-token={}", token.as_str())))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    assert_eq!(body.as_ref(), id.as_bytes());
}

#[tokio::test]
async fn test_sa_token_layer_injects_login_id_from_authorization_bearer() {
    let mgr = setup::shared_manager();
    let state = test_state();
    let id = setup::unique_login_id("actix_bearer");
    let token = mgr.login(&id).await.expect("login");

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state)).route(
        "/me",
        web::get().to(|ext: LoginIdExtractor| async move { HttpResponse::Ok().body(ext.0) }),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/me")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    assert_eq!(body.as_ref(), id.as_bytes());
}

#[tokio::test]
async fn test_optional_extractor_returns_none_without_token() {
    let state = test_state();

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state)).route(
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
async fn test_optional_extractor_returns_exact_token_when_present() {
    let mgr = setup::shared_manager();
    let state = test_state();
    let id = setup::unique_login_id("actix_opt");
    let token = mgr.login(&id).await.expect("login");

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state)).route(
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
    assert_eq!(
        std::str::from_utf8(body.as_ref()).expect("utf8"),
        token.as_str(),
        "body must equal the exact token value"
    );
}

// ── 失败路径 ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_login_id_extractor_returns_401_without_token() {
    let state = test_state();

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state)).route(
        "/protected",
        web::get().to(|_ext: LoginIdExtractor| async move { HttpResponse::Ok().body("ok") }),
    ))
    .await;

    let req = test::TestRequest::get().uri("/protected").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

/// 无 path_auth：过期 token 不注入 login_id → LoginIdExtractor 401。
#[tokio::test]
async fn test_login_id_extractor_returns_401_with_expired_token() {
    let mgr = setup::fresh_manager();
    let state = ActixState {
        manager: mgr.clone(),
    };
    let id = setup::unique_login_id("actix_exp");
    let token = mgr.login(&id).await.expect("login");
    setup::expire_token(&mgr, &token).await;

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state)).route(
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

// ── path_auth：SaTokenMiddleware ──────────────────────────────────────────

#[tokio::test]
async fn test_path_auth_middleware_include_exclude() {
    let mgr = setup::shared_manager();
    let state = test_state();
    let id = setup::unique_login_id("actix_path");
    let token = mgr.login(&id).await.expect("login");
    let path = PathAuthConfig::new()
        .include(vec!["/api/**".into()])
        .exclude(vec!["/api/public/**".into()]);

    let app = test::init_service(
        App::new()
            .wrap(SaTokenMiddleware::with_path_auth(state, path))
            .route(
                "/api/user",
                web::get()
                    .to(|ext: LoginIdExtractor| async move { HttpResponse::Ok().body(ext.0) }),
            )
            .route(
                "/api/public/info",
                web::get().to(|| async { HttpResponse::Ok().body("public") }),
            ),
    )
    .await;

    // SaTokenMiddleware 拒识返回 Err(ErrorUnauthorized)；call_service 会对 Err panic
    let req = test::TestRequest::get().uri("/api/user").to_request();
    let err = app
        .call(req)
        .await
        .expect_err("include path without token must reject");
    assert_eq!(err.as_response_error().status_code(), 401);

    let req = test::TestRequest::get()
        .uri("/api/public/info")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    assert_eq!(body.as_ref(), b"public");

    let req = test::TestRequest::get()
        .uri("/api/user")
        .insert_header(("sa-token", token.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    assert_eq!(body.as_ref(), id.as_bytes());
}

#[tokio::test]
async fn test_stputil_initialized_for_permission_smoke() {
    // 确认 Actix 测试二进制下 StpUtil 已挂共享 manager（权限写读不丢 Result）
    let _ = setup::shared_manager();
    let id = setup::unique_login_id("actix_perm_smoke");
    StpUtil::login(&id).await.expect("StpUtil login");
    StpUtil::add_permission(&id, "actix:smoke")
        .await
        .expect("add_permission");
    assert!(StpUtil::has_permission(&id, "actix:smoke").await);
}
