// Author: 金书记
//
//! sa-token-rust Poem 完整示例
//! 
//! 展示如何：
//! 1. 配置 sa-token
//! 2. 加载用户权限和角色
//! 3. 使用中间件和提取器
//! 4. 实现完整的认证流程

use std::sync::Arc;
use poem::{
    Route, Server, listener::TcpListener, 
    handler, web::Json, web::Data, EndpointExt,
    Result as PoemResult,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sa_token_plugin_poem::*;

/// API 错误类型
pub enum ApiError {
    Unauthorized(String),
    Forbidden(String),
    InternalError(String),
}

// sa_token_plugin_poem re-export 了 sa_token_core::SaTokenError，
// 二者是同一类型，只能实现一次 From（此前两份 impl 触发 E0119）。
impl From<SaTokenError> for ApiError {
    fn from(err: SaTokenError) -> Self {
        match err {
            SaTokenError::NotLogin => {
                ApiError::Unauthorized("User not logged in".to_string())
            }
            SaTokenError::PermissionDenied 
            | SaTokenError::PermissionDeniedDetail(_) => {
                ApiError::Forbidden("Permission denied".to_string())
            }
            SaTokenError::RoleDenied(_) => {
                ApiError::Forbidden("Role required".to_string())
            }
            _ => ApiError::InternalError(format!("Authentication error: {}", err)),
        }
    }
}

impl From<ApiError> for poem::Error {
    fn from(err: ApiError) -> Self {
        let (status, message) = match err {
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        
        poem::Error::from_string(
            serde_json::json!({
                "code": status.as_u16(),
                "message": message,
            }).to_string(),
            status
        )
    }
}

/// API 响应结构
#[derive(Debug, Serialize)]
struct ApiResponse<T: Serialize> {
    code: i32,
    message: String,
    data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            code: 0,
            message: "success".to_string(),
            data: Some(data),
        }
    }
    
    fn error(code: i32, message: String) -> Self {
        Self {
            code,
            message,
            data: None,
        }
    }
}

/// 登录请求
#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

/// 登录响应
#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
    user_id: String,
    permissions: Vec<String>,
    roles: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    
    tracing::info!("🚀 启动 sa-token-rust Poem 完整示例");
    
    // 1. 使用构建器模式创建 sa-token 状态
    let sa_token_state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .token_name("Authorization")
        .timeout(86400)  // 24小时
        .build();
    
    // StpUtil 已在 build() 时自动初始化
    
    // 3. 初始化测试用户的权限和角色
    init_test_permissions().await;
    
    // 4. 创建路由
    // Anonymous routes must be excluded; #[sa_ignore] does not skip this layer.
    // 匿名路由必须排除；#[sa_ignore] 不会跳过本层。
    let path_auth = PathAuthConfig::new()
        .include(vec!["/**".into()])
        .exclude(vec![
            "/".into(),
            "/api/health".into(),
            "/api/auth/login".into(),
        ]);

    let app = Route::new()
        // 公开接口（路径放行靠 PathAuthConfig::exclude）
        .at("/", poem::get(index))
        .at("/api/health", poem::get(health_check))
        .at("/api/auth/login", poem::post(login))
        
        // 需要登录的接口（使用宏）
        .at("/api/user/info", poem::get(user_info))
        .at("/api/user/permissions", poem::get(list_permissions))
        .at("/api/user/roles", poem::get(list_roles))
        
        // 需要权限的接口（使用宏自动检查）
        .at("/api/admin/users", poem::get(list_users))
        .at("/api/admin/config", poem::get(admin_config))
        
        // 应用中间件（Poem：用 SaTokenLayer::with_path_auth，非 Middleware::new）
        .with(SaTokenLayer::with_path_auth(sa_token_state.clone(), path_auth))
        .data(sa_token_state);
    
    tracing::info!("📡 服务器运行在 http://127.0.0.1:3000");
    tracing::info!("   试试访问: http://127.0.0.1:3000/api/health");
    tracing::info!("   登录接口: POST http://127.0.0.1:3000/api/auth/login");
    tracing::info!("");
    tracing::info!("💡 测试用户:");
    tracing::info!("   - admin/admin123  (管理员)");
    tracing::info!("   - user/user123    (普通用户)");
    tracing::info!("   - guest/guest123  (访客)");
    
    // 5. 启动服务器
    Server::new(TcpListener::bind("127.0.0.1:3000"))
        .run(app)
        .await
}

/// 初始化测试用户的权限和角色
async fn init_test_permissions() {
    tracing::info!("🔐 初始化测试用户权限...");
    
    // 管理员用户
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
    ).await.unwrap();
    
    StpUtil::set_roles(
        "admin",
        vec!["admin".to_string(), "user".to_string()],
    ).await.unwrap();
    
    tracing::info!("  ✓ 管理员 (admin) 权限已初始化");
    
    // 普通用户
    StpUtil::set_permissions(
        "user",
        vec![
            "user:list".to_string(),
            "user:view".to_string(),
        ],
    ).await.unwrap();
    
    StpUtil::set_roles(
        "user",
        vec!["user".to_string()],
    ).await.unwrap();
    
    tracing::info!("  ✓ 普通用户 (user) 权限已初始化");
    
    // 访客用户
    StpUtil::set_permissions(
        "guest",
        vec!["user:view".to_string()],
    ).await.unwrap();
    
    StpUtil::set_roles(
        "guest",
        vec!["guest".to_string()],
    ).await.unwrap();
    
    tracing::info!("  ✓ 访客 (guest) 权限已初始化");
    tracing::info!("✅ 所有测试用户权限初始化完成！\n");
}

// ==================== 公开接口 ====================

#[handler]
async fn index() -> &'static str {
    "Welcome to sa-token-rust Poem example! Visit /api/health to check health."
}

#[handler]
async fn health_check() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("OK".to_string()))
}

/// 登录接口
#[handler]
async fn login(
    Data(state): Data<&SaTokenState>,
    Json(req): Json<LoginRequest>,
) -> PoemResult<Json<ApiResponse<LoginResponse>>> {
    tracing::info!("🔑 用户登录请求: username={}", req.username);
    
    // 验证用户名密码（这里简化处理）
    let (user_id, valid) = match req.username.as_str() {
        "admin" if req.password == "admin123" => ("admin", true),
        "user" if req.password == "user123" => ("user", true),
        "guest" if req.password == "guest123" => ("guest", true),
        _ => ("", false),
    };
    
    if !valid {
        return Ok(Json(ApiResponse::error(401, "Invalid username or password".to_string())));
    }
    
    // 执行登录
    let token = state.manager
        .login(user_id)
        .await
        .map_err(|e| poem::Error::from_string(
            format!("登录失败: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR
        ))?;
    
    // 获取用户权限和角色
    let permissions = StpUtil::get_permissions(user_id).await;
    let roles = StpUtil::get_roles(user_id).await;
    
    tracing::info!(
        "✅ 用户 {} 登录成功，权限: {:?}, 角色: {:?}", 
        user_id, permissions, roles
    );
    
    Ok(Json(ApiResponse::success(LoginResponse {
        token: token.as_str().to_string(),
        user_id: user_id.to_string(),
        permissions,
        roles,
    })))
}

// ==================== 需要登录的接口 ====================

/// 获取用户信息（使用宏检查登录）
#[sa_check_login]
#[handler]
async fn user_info() -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    // 从当前上下文获取用户 ID
    // Get user ID from current context
    let login_id = StpUtil::get_login_id_as_string().await?;
    
    let permissions = StpUtil::get_permissions(&login_id).await;
    let roles = StpUtil::get_roles(&login_id).await;
    
    Ok(Json(ApiResponse::success(serde_json::json!({
        "user_id": login_id,
        "permissions": permissions,
        "roles": roles,
    }))))
}

/// 查询用户权限列表（使用宏检查登录）
#[sa_check_login]
#[handler]
async fn list_permissions() -> Result<Json<ApiResponse<Vec<String>>>, ApiError> {
    // 从当前上下文获取用户 ID
    let login_id = StpUtil::get_login_id_as_string().await?;
    
    let permissions = StpUtil::get_permissions(&login_id).await;
    
    Ok(Json(ApiResponse::success(permissions)))
}

/// 查询用户角色列表（使用宏检查登录）
#[sa_check_login]
#[handler]
async fn list_roles() -> Result<Json<ApiResponse<Vec<String>>>, ApiError> {
    // 从当前上下文获取用户 ID
    let login_id = StpUtil::get_login_id_as_string().await?;
    
    let roles = StpUtil::get_roles(&login_id).await;
    
    Ok(Json(ApiResponse::success(roles)))
}

// ==================== 需要权限的接口 ====================

/// 获取用户列表（需要 user:list 权限）
#[sa_check_permission("user:list")]
#[handler]
async fn list_users() -> Result<Json<ApiResponse<Vec<String>>>, ApiError> {
    let users = vec![
        "admin".to_string(),
        "user1".to_string(),
        "user2".to_string(),
    ];
    
    Ok(Json(ApiResponse::success(users)))
}

/// 管理员配置（需要 admin 角色）
#[sa_check_role("admin")]
#[handler]
async fn admin_config() -> Result<Json<ApiResponse<String>>, ApiError> {
    Ok(Json(ApiResponse::success("Admin configuration data".to_string())))
}
