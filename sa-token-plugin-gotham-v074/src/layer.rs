//! Gotham `Middleware` pipeline: **`GothamCapturedRequest`** + **`run_auth_flow`**, then `State` wrappers.
//! Gotham **`Middleware`**：**`GothamCapturedRequest`** + **`run_auth_flow`**，再写入 `State` 包装类型。
use gotham::handler::HandlerFuture;
use gotham::middleware::Middleware;
use gotham::state::State;
use sa_token_core::router::run_auth_flow;
use sa_token_plugin_common::SaTokenState;
use std::pin::Pin;

use crate::adapter::GothamCapturedRequest;

#[derive(Clone)]
pub struct SaTokenLayer {
    state: SaTokenState,
}

impl SaTokenLayer {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

impl Middleware for SaTokenLayer {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Pin<Box<HandlerFuture>>
    where
        Chain: FnOnce(State) -> Pin<Box<HandlerFuture>> + Send + 'static,
    {
        Box::pin(async move {
            // Capture from `State` synchronously: `HeaderMap` + `Uri` live in state for this stage.
            // 从 `State` 同步采集：此阶段 `HeaderMap` 与 `Uri` 位于 state 中。
            let token_name = self.state.manager.config.token_name.as_str();
            let adapter = GothamCapturedRequest::capture(&state, token_name);
            let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

            if let Some(ref t) = flow.token {
                state.put(crate::wrapper::TokenValueWrapper(t.clone()));
            }
            if let Some(ref id) = flow.login_id {
                state.put(crate::wrapper::LoginIdWrapper(id.clone()));
            }

            flow.run(chain(state)).await
        })
    }
}
