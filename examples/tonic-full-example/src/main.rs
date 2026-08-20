// Author: 金书记
//
// 中文 | English
// sa-token-rust Tonic gRPC 完整示例
// sa-token-rust Tonic gRPC Full Example
//
// 展示如何：| Demonstrates how to:
// 1. 配置 sa-token | Configure sa-token
// 2. 使用 SaTokenGrpcLayer Tower 层 | Use SaTokenGrpcLayer Tower layer
// 3. 配置 PathAuthConfig 区分公开/受保护 RPC | Configure PathAuthConfig for public/protected RPCs
// 4. 在 handler 中通过 get_login_id_from_request 获取已校验的登录 ID

use sa_token_plugin_tonic::*;
use std::sync::Arc;
use tonic::{Code, Request, Response, Status};

pub mod auth {
    tonic::include_proto!("auth");
}

// ============================================================================
// gRPC 服务实现 | gRPC Service Implementation
// ============================================================================

/// 中文: 认证服务实现
/// English: Authentication service implementation
pub struct AuthServiceImpl {
    state: SaTokenState,
}

impl AuthServiceImpl {
    /// 中文: 创建新的服务实例
    /// English: Create new service instance
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl auth::auth_service_server::AuthService for AuthServiceImpl {
    /// 中文: 健康检查（公开接口，PathAuthConfig exclude 中已排除）
    /// English: Health check (public endpoint, excluded in PathAuthConfig)
    async fn health_check(
        &self,
        _request: Request<auth::HealthCheckRequest>,
    ) -> Result<Response<auth::HealthCheckResponse>, Status> {
        tracing::info!("Health check requested");

        Ok(Response::new(auth::HealthCheckResponse {
            status: "OK".to_string(),
        }))
    }

    /// 中文: 登录接口（公开接口，PathAuthConfig exclude 中已排除）
    /// English: Login endpoint (public endpoint, excluded in PathAuthConfig)
    async fn login(
        &self,
        request: Request<auth::LoginRequest>,
    ) -> Result<Response<auth::LoginResponse>, Status> {
        let req = request.into_inner();
        tracing::info!("Login request: username={}", req.username);

        let (user_id, valid) = match req.username.as_str() {
            "admin" if req.password == "admin123" => ("admin", true),
            "user" if req.password == "user123" => ("user", true),
            "guest" if req.password == "guest123" => ("guest", true),
            _ => ("", false),
        };

        if !valid {
            return Err(Status::new(
                Code::Unauthenticated,
                "Invalid username or password",
            ));
        }

        let token = self
            .state
            .manager
            .login(user_id)
            .await
            .map_err(|e| Status::internal(format!("Login failed: {}", e)))?;

        let permissions = StpUtil::get_permissions(user_id).await;
        let roles = StpUtil::get_roles(user_id).await;

        tracing::info!(
            "User {} logged in, permissions: {:?}, roles: {:?}",
            user_id,
            permissions,
            roles
        );

        Ok(Response::new(auth::LoginResponse {
            token: token.as_str().to_string(),
            user_id: user_id.to_string(),
            permissions,
            roles,
        }))
    }

    /// 中文: 获取用户信息（需要登录，Layer 已校验并注入 SaTokenLoginId）
    /// English: Get user info (requires login, Layer has validated and injected SaTokenLoginId)
    async fn get_user_info(
        &self,
        request: Request<auth::UserInfoRequest>,
    ) -> Result<Response<auth::UserInfoResponse>, Status> {
        let login_id = get_login_id_from_request(&request)
            .ok_or_else(|| Status::unauthenticated("Not authenticated"))?;

        tracing::info!("GetUserInfo request from user: {}", login_id);

        let permissions = StpUtil::get_permissions(&login_id).await;
        let roles = StpUtil::get_roles(&login_id).await;

        Ok(Response::new(auth::UserInfoResponse {
            user_id: login_id,
            permissions,
            roles,
        }))
    }

    /// 中文: 获取权限列表（需要登录）
    /// English: Get permissions list (requires login)
    async fn get_permissions(
        &self,
        request: Request<auth::PermissionsListRequest>,
    ) -> Result<Response<auth::PermissionsListResponse>, Status> {
        let login_id = get_login_id_from_request(&request)
            .ok_or_else(|| Status::unauthenticated("Not authenticated"))?;

        tracing::info!("GetPermissions request from user: {}", login_id);

        let permissions = StpUtil::get_permissions(&login_id).await;

        Ok(Response::new(auth::PermissionsListResponse { permissions }))
    }

    /// 中文: 获取角色列表（需要登录）
    /// English: Get roles list (requires login)
    async fn get_roles(
        &self,
        request: Request<auth::RolesListRequest>,
    ) -> Result<Response<auth::RolesListResponse>, Status> {
        let login_id = get_login_id_from_request(&request)
            .ok_or_else(|| Status::unauthenticated("Not authenticated"))?;

        tracing::info!("GetRoles request from user: {}", login_id);

        let roles = StpUtil::get_roles(&login_id).await;

        Ok(Response::new(auth::RolesListResponse { roles }))
    }
}

// ============================================================================
// 初始化测试数据 | Initialize Test Data
// ============================================================================

async fn init_test_permissions() {
    tracing::info!("Initializing test user permissions...");

    StpUtil::set_permissions(
        "admin",
        vec![
            "user:list".to_string(),
            "user:create".to_string(),
            "user:update".to_string(),
            "user:delete".to_string(),
            "system:config".to_string(),
            "admin:*".to_string(),
        ],
    )
    .await
    .unwrap();

    StpUtil::set_roles("admin", vec!["admin".to_string(), "user".to_string()])
        .await
        .unwrap();

    StpUtil::set_permissions(
        "user",
        vec!["user:list".to_string(), "user:view".to_string()],
    )
    .await
    .unwrap();

    StpUtil::set_roles("user", vec!["user".to_string()])
        .await
        .unwrap();

    StpUtil::set_permissions("guest", vec!["user:view".to_string()])
        .await
        .unwrap();

    StpUtil::set_roles("guest", vec!["guest".to_string()])
        .await
        .unwrap();

    tracing::info!("All test user permissions initialized");
}

// ============================================================================
// 主函数 | Main Function
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    tracing::info!("Starting sa-token-rust Tonic gRPC Full Example");

    // 1. 创建 sa-token 状态 | Create sa-token state
    let sa_token_state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .token_name("satoken")
        .timeout(86400)
        .build();

    tracing::info!("SaToken state created");

    // 2. 初始化测试数据 | Initialize test data
    init_test_permissions().await;

    // 3. 配置 per-RPC 鉴权规则 | Configure per-RPC auth rules
    let path_config = PathAuthConfig::new()
        .include(vec!["/auth.AuthService/**".to_string()])
        .exclude(vec![
            "/auth.AuthService/HealthCheck".to_string(),
            "/auth.AuthService/Login".to_string(),
        ]);

    // 4. 创建 Tower 鉴权层 | Create Tower auth layer
    let grpc_auth_layer = SaTokenGrpcLayer::with_path_auth(sa_token_state.clone(), path_config);
    tracing::info!("SaTokenGrpcLayer created with PathAuthConfig");

    // 5. 启动服务器 | Start the server
    let addr = "0.0.0.0:3000".parse()?;

    tracing::info!("gRPC server listening on {}", addr);
    tracing::info!("Test users: admin/admin123, user/user123, guest/guest123");
    tracing::info!("Public RPCs: HealthCheck, Login");
    tracing::info!("Protected RPCs: GetUserInfo, GetPermissions, GetRoles");

    tonic::transport::Server::builder()
        .layer(
            tower::ServiceBuilder::new()
                .layer(grpc_auth_layer)
                .into_inner(),
        )
        .add_service(auth::auth_service_server::AuthServiceServer::new(
            AuthServiceImpl::new(sa_token_state.clone()),
        ))
        .serve(addr)
        .await?;

    Ok(())
}
