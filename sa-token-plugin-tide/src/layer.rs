// Author: 金书记
//
//! Tide Sa-Token layer

use sa_token_adapter::context::SaRequest;
use sa_token_adapter::utils::{parse_cookies, parse_query_string};
use sa_token_core::router::{PathAuthConfig, run_auth_flow};
use sa_token_plugin_common::{SaLoginId, SaTokenState};
use tide_017::{Middleware, Next, Request, Result};

pub(crate) struct TideRequestAdapter<'a, S> {
    req: &'a Request<S>,
}

impl<'a, S> TideRequestAdapter<'a, S> {
    pub(crate) fn new(req: &'a Request<S>) -> Self {
        Self { req }
    }
}

impl<S> SaRequest for TideRequestAdapter<'_, S> {
    fn get_header(&self, name: &str) -> Option<String> {
        self.req
            .header(name)
            .and_then(|h| h.get(0))
            .map(|v| v.as_str().to_string())
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        self.req
            .header("cookie")
            .and_then(|h| h.get(0))
            .and_then(|s| parse_cookies(s.as_str()).get(name).cloned())
    }

    fn get_param(&self, name: &str) -> Option<String> {
        self.req
            .url()
            .query()
            .and_then(|q| parse_query_string(q).get(name).cloned())
    }

    fn get_path(&self) -> String {
        self.req.url().path().to_string()
    }

    fn get_method(&self) -> String {
        self.req.method().to_string()
    }
}

/// Sa-Token layer for Tide with optional path-based authentication
#[derive(Clone)]
pub struct SaTokenLayer {
    state: SaTokenState,
    path_config: Option<PathAuthConfig>,
}

impl SaTokenLayer {
    pub fn new(state: SaTokenState) -> Self {
        Self {
            state,
            path_config: None,
        }
    }

    pub fn with_path_auth(state: SaTokenState, config: PathAuthConfig) -> Self {
        Self {
            state,
            path_config: Some(config),
        }
    }
}

#[tide_017::utils::async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for SaTokenLayer {
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> Result {
        let adapter = TideRequestAdapter::new(&req);
        let flow = run_auth_flow(&adapter, &self.state.manager, self.path_config.as_ref()).await;

        if flow.should_reject() {
            return Ok(tide_017::Response::builder(tide_017::StatusCode::Unauthorized).build());
        }

        if let Some(t) = &flow.token {
            req.set_ext(t.clone());
        }
        if let Some(id) = &flow.login_id {
            req.set_ext(SaLoginId(id.clone()));
        }

        Ok(flow.run(next.run(req)).await)
    }
}

/// Extract token using shared router logic and live config.
/// 使用共享 router 逻辑与当前配置提取 token。
pub fn extract_token_from_request<State>(
    req: &Request<State>,
    config: &sa_token_core::SaTokenConfig,
) -> Option<String> {
    let adapter = TideRequestAdapter::new(req);
    sa_token_core::router::extract_token_from(&adapter, config)
}
