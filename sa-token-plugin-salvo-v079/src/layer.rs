//! Salvo **`Handler`** implementing the shared auth pipeline / 实现统一鉴权流水线的 Salvo **`Handler`**。
use sa_token_core::router::{PathAuthConfig, run_auth_flow};
use sa_token_plugin_common::SaTokenState;
use salvo::http::StatusCode;
use salvo::{Depot, FlowCtrl, Handler, Request, Response};

use crate::adapter::SalvoCapturedRequest;

/// Optional **`PathAuthConfig`**: if set, **`should_reject`** → 401 without `call_next`.
/// 可选 **`PathAuthConfig`**：命中拒绝条件时直接 **401**，不调用后续。
///
/// When `path_config` is `None`, successful login data is written to **`Depot`** (`sa_token`, `sa_login_id`).
/// `path_config` 为 `None` 时，将 token / login_id 写入 **`Depot`**（`sa_token`、`sa_login_id`）。
#[derive(Clone)]
pub struct SaTokenLayer {
    state: SaTokenState,
    path_config: Option<PathAuthConfig>,
}

impl SaTokenLayer {
    /// No path rules; depot + context only after validation. | 无路径规则，仅校验后写 Depot + 上下文。
    pub fn new(state: SaTokenState) -> Self {
        Self {
            state,
            path_config: None,
        }
    }

    /// Enable Ant-style include/exclude + optional login-id validator (**`PathAuthConfig`**).
    /// 启用路径包含/排除与可选登录 id 校验（**`PathAuthConfig`**）。
    pub fn with_path_auth(state: SaTokenState, config: PathAuthConfig) -> Self {
        Self {
            state,
            path_config: Some(config),
        }
    }
}

#[salvo::async_trait]
impl Handler for SaTokenLayer {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        // Snapshot before `.await`: avoid borrowing `req` across `run_auth_flow`.
        // 在 `.await` 前快照：避免跨 `run_auth_flow` 仍借用 `req`。
        let adapter =
            SalvoCapturedRequest::capture(req, self.state.manager.config.token_name.as_str());
        let flow = run_auth_flow(&adapter, &self.state.manager, self.path_config.as_ref()).await;

        if flow.should_reject() {
            res.status_code(StatusCode::UNAUTHORIZED);
            return;
        }

        if self.path_config.is_none() {
            if let Some(ref t) = flow.token {
                depot.insert("sa_token", t.clone());
            }
            if let Some(ref id) = flow.login_id {
                depot.insert("sa_login_id", id.clone());
            }
        }

        flow.run(ctrl.call_next(req, depot, res)).await;
    }
}

/// Extract token using snapshot + config-aware router helper.
/// 快照 + 尊重配置的 router 助手提取 token。
pub fn extract_token_from_request(
    req: &Request,
    config: &sa_token_core::SaTokenConfig,
) -> Option<String> {
    let cap = SalvoCapturedRequest::capture(req, config.token_name.as_str());
    sa_token_core::router::extract_token_from(&cap, config)
}
