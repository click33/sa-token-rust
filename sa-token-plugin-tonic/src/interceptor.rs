// Author: 金书记
//
// 中文 | English
// gRPC 认证拦截器模块 | gRPC authentication interceptor module
//
//! 中文: 本模块提供 gRPC 专用的认证拦截器与辅助函数
//! English: This module provides gRPC-specific authentication interceptors and helper functions
//!
//! 中文: 推荐使用 `SaTokenGrpcLayer`（Tower 层）；本模块的 `GrpcServerInterceptor` 为备选方案
//! English: Prefer `SaTokenGrpcLayer` (Tower layer); `GrpcServerInterceptor` here is an alternative

use tonic::{Code, Request, Status};

use crate::adapter::TonicCapturedRequest;
use crate::error::{SaTokenBearerToken, SaTokenLoginId};
use sa_token_core::error::messages;
use sa_token_core::router::{PathAuthConfig, run_auth_flow};
use sa_token_plugin_common::SaTokenState;

// ============================================================================
// 中文: gRPC 服务端拦截器
// English: gRPC Server Interceptor
// ============================================================================

/// 中文: gRPC 服务端认证拦截器
/// English: gRPC server interceptor for authentication
///
/// 中文: 内部通过 `block_in_place` + `block_on` 在同步上下文中执行 `run_auth_flow`
/// English: Internally uses `block_in_place` + `block_on` to run `run_auth_flow` in sync context
#[derive(Clone)]
pub struct GrpcServerInterceptor {
    state: SaTokenState,
    path_config: Option<PathAuthConfig>,
}

impl GrpcServerInterceptor {
    /// 中文: 创建新的服务端拦截器（无路径规则）
    /// English: Create a new server interceptor (no path rules)
    pub fn new(state: SaTokenState) -> Self {
        Self {
            state,
            path_config: None,
        }
    }

    /// 中文: 创建带路径鉴权的拦截器
    /// English: Create interceptor with path-based authentication
    pub fn with_path_auth(state: SaTokenState, config: PathAuthConfig) -> Self {
        Self {
            state,
            path_config: Some(config),
        }
    }

    /// 中文: 获取认证状态
    /// English: Get the authentication state
    pub fn state(&self) -> &SaTokenState {
        &self.state
    }

    /// 中文: 在同步拦截器上下文中执行完整鉴权流水线
    /// English: Run full auth pipeline in sync interceptor context
    fn run_flow_sync(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        path: String,
    ) -> sa_token_core::router::AuthFlowResult {
        let captured = TonicCapturedRequest::from_metadata(metadata, path, "GRPC");
        let state = self.state.clone();
        let path_config = self.path_config.clone();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                run_auth_flow(&captured, &state.manager, path_config.as_ref()).await
            })
        })
    }
}

impl tonic::service::Interceptor for GrpcServerInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        // 中文: 若 Tower Layer 已写入 login_id，直接透传（避免重复校验）
        // English: If Tower Layer already wrote login_id, pass through (avoid double validation)
        if req.extensions().get::<SaTokenLoginId>().is_some() {
            return Ok(req);
        }

        let path = TonicCapturedRequest::resolve_grpc_path(&req);
        let flow = self.run_flow_sync(req.metadata(), path);

        if flow.should_reject() {
            return Err(Status::new(Code::Unauthenticated, messages::AUTH_ERROR));
        }

        if let Some(login_id) = flow.login_id {
            req.extensions_mut().insert(SaTokenLoginId(login_id));
        }
        if let Some(token) = flow.token {
            req.extensions_mut().insert(SaTokenBearerToken(token));
        }

        Ok(req)
    }
}

// ============================================================================
// 中文: 请求上下文辅助函数
// English: Request context helper functions
// ============================================================================

/// 中文: 从请求扩展中提取已校验的登录 ID
/// English: Extract validated login ID from request extensions
pub fn get_login_id_from_request<T>(request: &Request<T>) -> Option<String> {
    request
        .extensions()
        .get::<SaTokenLoginId>()
        .map(|x| x.0.clone())
}

/// 中文: 从请求扩展中提取原始 Bearer Token
/// English: Extract raw Bearer Token from request extensions
pub fn get_bearer_token_from_request<T>(
    request: &Request<T>,
) -> Option<sa_token_core::token::TokenValue> {
    request
        .extensions()
        .get::<SaTokenBearerToken>()
        .map(|x| x.0.clone())
}

/// 中文: 从请求中验证 token 并获取登录 ID（异步，兼容旧代码）
/// English: Validate token from request and get login ID (async, legacy compat)
pub async fn validate_token_from_request<T>(
    state: &SaTokenState,
    request: &Request<T>,
) -> Result<String, Status> {
    if let Some(id) = get_login_id_from_request(request) {
        return Ok(id);
    }

    let path = TonicCapturedRequest::resolve_grpc_path(request);
    let captured = TonicCapturedRequest::from_metadata(request.metadata(), path, "GRPC");
    let flow = run_auth_flow(&captured, &state.manager, None).await;

    match flow.login_id {
        Some(id) => Ok(id),
        None => Err(Status::unauthenticated(messages::AUTH_ERROR)),
    }
}

/// 中文: 从 gRPC metadata 创建请求适配器
/// English: Create a request adapter from gRPC metadata
pub fn create_request_adapter(
    metadata: &tonic::metadata::MetadataMap,
    method: &str,
    path: &str,
) -> crate::adapter::TonicRequestAdapter {
    crate::adapter::TonicRequestAdapter::from_metadata(
        metadata,
        method.to_string(),
        path.to_string(),
    )
}

// ============================================================================
// 中文: 权限检查辅助函数
// English: Permission check helper functions
// ============================================================================

/// 中文: 检查登录 ID 是否具有指定权限
/// English: Check if a login_id has the specified permission
pub async fn check_permission(login_id: &str, permission: &str) -> bool {
    sa_token_core::StpUtil::has_permission(login_id, permission).await
}

/// 中文: 检查登录 ID 是否具有任意一个指定权限
/// English: Check if a login_id has any of the specified permissions
pub async fn check_permissions(login_id: &str, permissions: &[&str]) -> bool {
    for perm in permissions {
        if sa_token_core::StpUtil::has_permission(login_id, perm).await {
            return true;
        }
    }
    false
}

/// 中文: 检查登录 ID 是否具有指定角色
/// English: Check if a login_id has the specified role
pub async fn check_role(login_id: &str, role: &str) -> bool {
    sa_token_core::StpUtil::has_role(login_id, role).await
}

/// 中文: 检查登录 ID 是否具有任意一个指定角色
/// English: Check if a login_id has any of the specified roles
pub async fn check_roles(login_id: &str, roles: &[&str]) -> bool {
    for r in roles {
        if sa_token_core::StpUtil::has_role(login_id, r).await {
            return true;
        }
    }
    false
}

// ============================================================================
// 中文: 单元测试
// English: Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_permission() {
        use sa_token_storage_memory::MemoryStorage;
        use std::sync::Arc;

        let _state = SaTokenState::builder()
            .storage(Arc::new(MemoryStorage::new()))
            .build();

        let login_id = "test_user";
        let _token = sa_token_core::StpUtil::login(login_id.to_string()).await;
        let _ = sa_token_core::StpUtil::add_role(login_id, "admin").await;

        assert!(!check_permission(login_id, "user:read").await);

        let _ = sa_token_core::StpUtil::add_permission(login_id, "user:read").await;
        assert!(check_permission(login_id, "user:read").await);
    }
}
