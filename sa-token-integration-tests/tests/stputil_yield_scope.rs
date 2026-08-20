//! `StpUtil::*_current` 在多 worker 下调度后仍可用（共享全局 `SaTokenManager` / `StpUtil`）。
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use actix_web::{App, HttpResponse, test, web};
use axum::body::{Body, to_bytes};
use axum_08 as axum;
use http::{Request, Response};
use sa_token_core::{SaTokenConfig, StpUtil};
use sa_token_plugin_actix_web_v4::{MemoryStorage, SaTokenLayer, SaTokenState as ActixState};
use sa_token_plugin_axum::{SaTokenLayer as AxumSaLayer, SaTokenState as AxumState};
use tower::{Layer, Service, ServiceExt};
use tower_08 as tower;

fn shared_manager() -> Arc<sa_token_core::SaTokenManager> {
    static M: OnceLock<Arc<sa_token_core::SaTokenManager>> = OnceLock::new();
    M.get_or_init(|| {
        let storage = Arc::new(MemoryStorage::new());
        Arc::new(SaTokenConfig::builder().storage(storage).build())
    })
    .clone()
}

#[derive(Clone)]
struct YieldThenLoginIdSvc;

impl Service<Request<Body>> for YieldThenLoginIdSvc {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        Box::pin(async move {
            for _ in 0..32 {
                tokio::task::yield_now().await;
            }
            let id = StpUtil::get_login_id_as_string()
                .await
                .expect("expected login id in context");
            Ok(Response::new(Body::from(id)))
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn axum_layer_survives_yield_for_stputil_current() {
    let mgr = shared_manager();
    let state = AxumState::from_manager((*mgr).clone());

    let token = mgr.login("u-scope-axum".to_string()).await.expect("login");

    let mut svc = AxumSaLayer::new(state).layer(YieldThenLoginIdSvc);

    let req = Request::builder()
        .uri("/")
        .header("sa-token", token.as_str())
        .body(Body::empty())
        .unwrap();

    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(req)
        .await
        .expect("call");

    assert_eq!(res.status(), http::StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], b"u-scope-axum");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actix_layer_survives_yield_for_stputil_current() {
    let mgr = shared_manager();
    let state = ActixState {
        manager: mgr.clone(),
    };

    let token = mgr.login("u-scope-actix".to_string()).await.expect("login");

    let app = test::init_service(App::new().wrap(SaTokenLayer::new(state.clone())).route(
        "/me",
        web::get().to(|| async move {
            for _ in 0..32 {
                tokio::task::yield_now().await;
            }
            let id = StpUtil::get_login_id_as_string().await.expect("login id");
            HttpResponse::Ok().body(id)
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
    assert_eq!(body.as_ref(), b"u-scope-actix");
}
