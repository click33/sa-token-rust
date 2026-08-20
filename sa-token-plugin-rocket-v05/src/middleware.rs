// Author: 金书记
//
//! Rocket Fairings sharing the same **`run_auth_flow`** rules as [`SaTokenLayer`](crate::layer::SaTokenLayer) (see each `on_request`).
//! 与 [`SaTokenLayer`](crate::layer::SaTokenLayer) 共用 **`run_auth_flow`** 规则的 Fairing（详见各 `on_request`）。

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{ContentType, Status};
use rocket::{Data, Request, Response};
use sa_token_core::router::run_auth_flow;
use sa_token_plugin_common::rejection;

use crate::SaTokenState;
use crate::adapter::RocketCapturedRequest;

/// sa-token Fairing - 提取并验证 token
pub struct SaTokenFairing {
    state: SaTokenState,
}

impl SaTokenFairing {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

#[rocket::async_trait]
impl Fairing for SaTokenFairing {
    fn info(&self) -> Info {
        Info {
            name: "SaToken Authentication",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _data: &mut Data<'_>) {
        let adapter =
            RocketCapturedRequest::capture(request, self.state.manager.config.token_name.as_str());
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        if let Some(ref t) = flow.token {
            request.local_cache(|| Some(t.clone()));
        }
        if let Some(ref id) = flow.login_id {
            request.local_cache(|| Some(id.clone()));
        }
    }
}

/// sa-token 登录检查 Fairing - 强制要求登录
pub struct SaCheckLoginFairing {
    state: SaTokenState,
}

impl SaCheckLoginFairing {
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

#[rocket::async_trait]
impl Fairing for SaCheckLoginFairing {
    fn info(&self) -> Info {
        Info {
            name: "SaToken Check Login",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _data: &mut Data<'_>) {
        let adapter =
            RocketCapturedRequest::capture(request, self.state.manager.config.token_name.as_str());
        let flow = run_auth_flow(&adapter, &self.state.manager, None).await;

        if flow.login_id.is_some() {
            if let Some(ref t) = flow.token {
                request.local_cache(|| Some(t.clone()));
            }
            if let Some(ref id) = flow.login_id {
                request.local_cache(|| Some(id.clone()));
            }
            return;
        }

        request.local_cache(|| Some("unauthorized"));
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        // 检查是否标记为未授权
        if request.local_cache(|| None::<&str>).is_some()
            && *request.local_cache(|| None::<&str>) == Some("unauthorized")
        {
            response.set_status(Status::Unauthorized);
            let body = rejection::unauthorized_json().to_string();
            response.set_sized_body(body.len(), std::io::Cursor::new(body));
        }
    }
}

/// sa-token 权限检查 Fairing - 强制要求特定权限
pub struct SaCheckPermissionFairing {
    // Rocket 的 Fairing 生命周期要求保留该字段以满足 trait 约束，
    // 但当前实现路径不读取它；P8 收敛插件层时评估删除。
    #[allow(dead_code)]
    state: SaTokenState,
    permission: String,
}

impl SaCheckPermissionFairing {
    pub fn new(state: SaTokenState, permission: impl Into<String>) -> Self {
        Self {
            state,
            permission: permission.into(),
        }
    }
}

#[rocket::async_trait]
impl Fairing for SaCheckPermissionFairing {
    fn info(&self) -> Info {
        Info {
            name: "SaToken Check Permission",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _data: &mut Data<'_>) {
        // 检查是否有登录ID
        if let Some(login_id) = request.local_cache(|| None::<String>).clone() {
            // 检查权限
            if sa_token_core::StpUtil::has_permission(&login_id, &self.permission).await {
                return;
            }
        }

        // 无权限，标记为禁止访问
        request.local_cache(|| Some("forbidden"));
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        // 检查是否标记为禁止访问
        if request.local_cache(|| None::<&str>).is_some()
            && *request.local_cache(|| None::<&str>) == Some("forbidden")
        {
            response.set_status(Status::Forbidden);
            response.set_header(ContentType::JSON);
            let body = rejection::forbidden_json(None).to_string();
            response.set_sized_body(body.len(), std::io::Cursor::new(body));
        }
    }
}

/// sa-token 角色检查 Fairing - 强制要求特定角色
pub struct SaCheckRoleFairing {
    // Rocket 的 Fairing 生命周期要求保留该字段以满足 trait 约束，
    // 但当前实现路径不读取它；P8 收敛插件层时评估删除。
    #[allow(dead_code)]
    state: SaTokenState,
    role: String,
}

impl SaCheckRoleFairing {
    pub fn new(state: SaTokenState, role: impl Into<String>) -> Self {
        Self {
            state,
            role: role.into(),
        }
    }
}

#[rocket::async_trait]
impl Fairing for SaCheckRoleFairing {
    fn info(&self) -> Info {
        Info {
            name: "SaToken Check Role",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _data: &mut Data<'_>) {
        // 检查是否有登录ID
        if let Some(login_id) = request.local_cache(|| None::<String>).clone() {
            // 检查角色
            if sa_token_core::StpUtil::has_role(&login_id, &self.role).await {
                return;
            }
        }

        // 无角色，标记为禁止访问
        request.local_cache(|| Some("forbidden_role"));
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        // 检查是否标记为禁止访问
        if request.local_cache(|| None::<&str>).is_some()
            && *request.local_cache(|| None::<&str>) == Some("forbidden_role")
        {
            response.set_status(Status::Forbidden);
            response.set_header(ContentType::JSON);
            let body = rejection::forbidden_role_json().to_string();
            response.set_sized_body(body.len(), std::io::Cursor::new(body));
        }
    }
}
