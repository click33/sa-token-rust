//! Tower `Transform` + `Service`: runs **`run_auth_flow`**, writes extensions, runs inner inside **`AuthFlowResult::run`** (task-local ctx).
//! Tower `Transform` / `Service`：执行 **`run_auth_flow`**，写 extensions，在 **`AuthFlowResult::run`** 内执行内层（task-local 上下文）。
use actix_web::{
    Error, HttpMessage,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use sa_token_core::router::run_auth_flow;
use sa_token_plugin_common::{SaLoginId, SaTokenState};
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;

use crate::adapter::ActixRequestAdapter;

/// Primary entry layer for actix-web token context (uses shared router pipeline).
/// 在 actix-web 上建立 token 上下文的主入口 Layer（走共享 router 流水线）。
#[derive(Clone)]
pub struct SaTokenLayer {
    state: SaTokenState,
}

impl SaTokenLayer {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SaTokenLayer
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SaTokenLayerService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SaTokenLayerService {
            service: Rc::new(service),
            state: self.state.clone(),
        }))
    }
}

pub struct SaTokenLayerService<S> {
    service: Rc<S>,
    state: SaTokenState,
}

impl<S, B> Service<ServiceRequest> for SaTokenLayerService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let state = self.state.clone();

        Box::pin(async move {
            let adapter = ActixRequestAdapter::new(req.request());
            let flow = run_auth_flow(&adapter, &state.manager, None).await;

            if let Some(t) = &flow.token {
                req.extensions_mut().insert(t.clone());
            }
            if let Some(id) = &flow.login_id {
                req.extensions_mut().insert(SaLoginId(id.clone()));
            }

            flow.run(service.call(req)).await
        })
    }
}
