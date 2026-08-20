//! Ntex `Middleware`: **`run_auth_flow`** via **`NtexCapturedRequest`**; optional path auth returns JSON **401**.
//! Ntex **`Middleware`**：通过 **`NtexCapturedRequest`** 调用 **`run_auth_flow`**；路径鉴权失败返回 JSON **401**。
use ntex::service::{Middleware, Service, ServiceCtx};
use ntex::web::error::InternalError;
use ntex::web::{Error, Error as WebError, ErrorRenderer, WebRequest, WebResponse};
use sa_token_core::router::PathAuthConfig;
use sa_token_core::router::run_auth_flow;
use sa_token_plugin_common::{SaLoginId, SaTokenState, rejection};

use crate::adapter::NtexCapturedRequest;

/// Cloneable wrapper passed to **`Middleware::create`**. | 可克隆包装，传给 **`Middleware::create`**。
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

    /// Same semantics as Salvo `with_path_auth` / 与 Salvo **`with_path_auth`** 语义一致。
    pub fn with_path_auth(state: SaTokenState, config: PathAuthConfig) -> Self {
        Self {
            state,
            path_config: Some(config),
        }
    }
}

impl<S> Middleware<S> for SaTokenLayer {
    type Service = SaTokenMiddleware<S>;

    fn create(&self, service: S) -> Self::Service {
        SaTokenMiddleware {
            service,
            state: self.state.clone(),
            path_config: self.path_config.clone(),
        }
    }
}

/// Inner service: snapshot → **`run_auth_flow`** → extensions + context. | 内层服务：快照 → 流水线 → extensions + 上下文。
pub struct SaTokenMiddleware<S> {
    service: S,
    state: SaTokenState,
    path_config: Option<PathAuthConfig>,
}

impl<S, Err> Service<WebRequest<Err>> for SaTokenMiddleware<S>
where
    S: Service<WebRequest<Err>, Response = WebResponse, Error = Error>,
    Err: ErrorRenderer,
{
    type Response = WebResponse;
    type Error = Error;

    async fn call(
        &self,
        req: WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        // Avoid borrowing `WebRequest` across `run_auth_flow` await.
        // 避免跨 `run_auth_flow` 的 await 仍借用 `WebRequest`。
        let adapter =
            NtexCapturedRequest::capture(&req, self.state.manager.config.token_name.as_str());
        let flow = run_auth_flow(&adapter, &self.state.manager, self.path_config.as_ref()).await;

        if flow.should_reject() {
            return Err(WebError::from(InternalError::new(
                rejection::unauthorized_json().to_string(),
                ntex::http::StatusCode::UNAUTHORIZED,
            )));
        }

        if let Some(ref t) = flow.token {
            req.extensions_mut().insert(t.clone());
        }
        if let Some(ref id) = flow.login_id {
            req.extensions_mut().insert(SaLoginId(id.clone()));
        }
        req.extensions_mut().insert(flow.context.clone());

        flow.run(ctx.call(&self.service, req)).await
    }
}
