//! `SaTokenLayer` Fairing: runs shared **`run_auth_flow`**, then sets **`SaTokenContext`** / clears after response.
//! `SaTokenLayer` Fairing：执行统一的 **`run_auth_flow`**，设置 **`SaTokenContext`**，响应后清理。
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Data, Request, Response};
use sa_token_core::SaTokenContext;
use sa_token_plugin_common::SaTokenState;

use crate::adapter::RocketCapturedRequest;

/// Rocket Fairing using **`RocketCapturedRequest`** + **`run_auth_flow`** (rocket-core pipeline).
/// 使用 **`RocketCapturedRequest`** + **`run_auth_flow`**（rocket-core 流水线）的 Fairing。
pub struct SaTokenLayer {
    state: SaTokenState,
}

impl SaTokenLayer {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

#[rocket::async_trait]
impl Fairing for SaTokenLayer {
    fn info(&self) -> Info {
        Info {
            name: "Sa-Token Authentication",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _: &mut Data<'_>) {
        let adapter =
            RocketCapturedRequest::capture(req, self.state.manager.config.token_name.as_str());
        let flow = sa_token_core::router::run_auth_flow(&adapter, &self.state.manager, None).await;

        if let Some(ref t) = flow.token {
            req.local_cache(|| Some(t.clone()));
        }
        if let Some(ref id) = flow.login_id {
            req.local_cache(|| Some(id.clone()));
        }

        // 1) 跨 await 串号时 thread_local 兜底（旧 StpUtil::*_current 同步路径）
        SaTokenContext::set_current(flow.context.clone());
        // 2) 推荐：请求级 Arc，供 `SaCtx` guard 读取（见 `extractor::SaCtx`）
        req.local_cache(|| std::sync::Arc::new(flow.context));
    }

    async fn on_response<'r>(&self, _req: &'r Request<'_>, _res: &mut Response<'r>) {
        SaTokenContext::clear();
    }
}
