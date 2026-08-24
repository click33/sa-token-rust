// Author: 金书记
//
//! sa-token-rust Axum 完整示例
//! 
//! 展示如何：
//! 1. 配置 sa-token
//! 2. 加载用户权限和角色
//! 3. 使用认证宏
//! 4. 实现完整的认证流程

use std::sync::Arc;
use std::collections::HashMap;
use axum::{
    Router,
    routing::{get, post},
    Json,
    extract::State,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sa_token_plugin_axum::*;

mod auth;
mod stp_util_demo;
mod login_id_demo;
mod context_demo;

use auth::*;

/// 应用状态
#[derive(Clone)]
pub struct AppState {
    pub sa_token: SaTokenState,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    tracing::info!("🚀 启动 sa-token-rust Axum 完整示例");

    // 1. 使用构建器模式创建 sa-token 状态（一行搞定！）
    let sa_token_state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .token_name("Authorization")
        .timeout(86400)  // 24小时
        .token_style(sa_token_plugin_axum::TokenStyle::Random64)
        .build();
    
    // StpUtil 已在 build() 时自动初始化
    
    // 2. 初始化测试用户的权限和角色（使用 StpUtil）
    init_test_permissions().await;
    
    // 3.1 运行 StpUtil 演示（可选）
    if std::env::var("DEMO_STP_UTIL").is_ok() {
        tracing::info!("\n");
        if let Err(e) = stp_util_demo::demo_stp_util().await {
            tracing::error!("StpUtil 演示失败: {}", e);
        }
        tracing::info!("\n");
    }
    
    // 3.2 运行 LoginId 多类型支持演示（可选）
    if std::env::var("DEMO_LOGIN_ID").is_ok() {
        tracing::info!("\n");
        if let Err(e) = login_id_demo::demo_login_id_types().await {
            tracing::error!("LoginId 演示失败: {}", e);
        }
        tracing::info!("\n");
    }
    
    // 3. 创建应用状态
    let app_state = AppState {
        sa_token: sa_token_state,
    };
    
    // 4. 创建路由
    let app = Router::new()
        // 公开接口（不需要认证）
        .route("/", get(index))
        .route("/api/health", get(health_check))
        .route("/api/login", post(login))
        .route("/api/register", post(register))
        
        // 需要登录的接口
        .route("/api/user/info", get(user_info))
        .route("/api/user/profile", get(user_profile))
        
        // 需要特定权限的接口
        .route("/api/user/list", get(list_users))
        .route("/api/user/delete", post(delete_user))
        
        // 需要管理员角色的接口
        .route("/api/admin/panel", get(admin_panel))
        .route("/api/admin/stats", get(admin_stats))
        
        // 需要多个权限的接口
        .route("/api/user/manage", post(manage_user))
        
        // 权限管理接口（需要 admin 角色）
        .route("/api/permission/list", get(list_permissions))
        .route("/api/permission/add", post(add_permission))
        .route("/api/permission/remove", post(remove_permission))
        .route("/api/role/list", get(list_roles))
        
        // StpUtil 演示接口
        .route("/api/demo/stp-util", get(demo_stp_util_api));

    // Anonymous routes must be excluded; #[sa_ignore] does not skip this layer.
    // 匿名路由必须排除；#[sa_ignore] 不会跳过本层。
    let path_auth = PathAuthConfig::new()
        .include(vec!["/**".into()])
        .exclude(vec![
            "/".into(),
            "/api/health".into(),
            "/api/register".into(),
            "/api/login".into(),
            "/api/demo/stp-util".into(),
        ]);

    let app = app
        .layer(SaTokenLayer::with_path_auth(
            app_state.sa_token.clone(),
            path_auth,
        ))
        .with_state(app_state);
    
    // 6. 启动服务器
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("📡 服务器运行在 http://localhost:3000");
    tracing::info!("\n📝 测试账号：");
    tracing::info!("   admin / admin123 (拥有所有权限)");
    tracing::info!("   user / user123 (普通用户权限)");
    tracing::info!("   guest / guest123 (访客权限)");
    
    axum::serve(listener, app).await?;
    
    Ok(())
}

/// 初始化测试用户的权限和角色
/// 
/// 使用 StpUtil 来管理权限和角色，简单高效！
async fn init_test_permissions() {
    tracing::info!("🔐 初始化测试用户权限（使用 StpUtil）...");
    
    // ========== 管理员用户 (admin) ==========
    StpUtil::set_permissions(
        "admin",
        vec![
            "user:list".to_string(),
            "user:create".to_string(),
            "user:update".to_string(),
            "user:delete".to_string(),
            "user:read".to_string(),
            "user:write".to_string(),
            "system:config".to_string(),
            "system:log".to_string(),
            "admin:*".to_string(),
        ],
    ).await.unwrap();
    
    StpUtil::set_roles(
        "admin",
        vec!["admin".to_string(), "user".to_string()],
    ).await.unwrap();
    
    tracing::info!("  ✓ admin: 权限=[user:*, system:*, admin:*], 角色=[admin, user]");
    tracing::info!("  ✓ admin: permissions=[user:*, system:*, admin:*], roles=[admin, user]");
    
    // ========== 普通用户 (user) ==========
    StpUtil::set_permissions(
        "user",
        vec![
            "user:list".to_string(),
            "user:view".to_string(),
            "profile:edit".to_string(),
        ],
    ).await.unwrap();
    
    StpUtil::set_roles(
        "user",
        vec!["user".to_string()],
    ).await.unwrap();
    
    tracing::info!("  ✓ user: 权限=[user:list, user:view, profile:edit], 角色=[user]");
    
    // ========== 访客用户 (guest) ==========
    StpUtil::set_permissions(
        "guest",
        vec!["user:view".to_string()],
    ).await.unwrap();
    
    StpUtil::set_roles(
        "guest",
        vec!["guest".to_string()],
    ).await.unwrap();
    
    tracing::info!("  ✓ guest: 权限=[user:view], 角色=[guest]");
    tracing::info!("✅ 权限初始化完成！\n");
}

// ==================== 公开接口（路径放行靠 PathAuthConfig::exclude）====================

async fn index() -> &'static str {
    "Welcome to sa-token-rust! Visit /api/health to check health."
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "sa-token-rust",
        "version": "0.2.0"
    }))
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<ApiResponse<String>>, ApiError> {
    // 实际应用中应该存储到数据库
    tracing::info!("用户注册: {}", req.username);
    
    Ok(Json(ApiResponse::success("注册成功，请登录".to_string())))
}

// ==================== 需要登录的接口 ====================

#[sa_check_login]
async fn user_info() -> Result<Json<ApiResponse<UserInfo>>, ApiError> {
    // 从当前上下文获取用户 ID（StpUtil 会自动从 SaTokenContext 中获取）
    // Get user ID from current context (StpUtil automatically gets from SaTokenContext)
    let login_id = StpUtil::get_login_id_as_string().await
        .map_err(|e| ApiError::Unauthorized(format!("获取用户ID失败: {}", e)))?;
    
    // 根据 login_id 获取用户信息（实际应用中应该查询数据库）
    // Get user info based on login_id (in real app, query database)
    let info = UserInfo {
        id: login_id.clone(),
        username: login_id.clone(),
        nickname: match login_id.as_str() {
            "admin" => "管理员",
            "user" => "普通用户",
            "guest" => "访客",
            _ => "未知用户",
        }.to_string(),
        email: Some(format!("{}@example.com", login_id)),
    };
    
    Ok(Json(ApiResponse::success(info)))
}

#[sa_check_login]
async fn user_profile() -> Result<Json<ApiResponse<String>>, ApiError> {
    Ok(Json(ApiResponse::success("用户资料".to_string())))
}

// ==================== 需要权限的接口 ====================

#[sa_check_permission("user:list")]
async fn list_users() -> Result<Json<ApiResponse<Vec<UserInfo>>>, ApiError> {
    let users = vec![
        UserInfo {
            id: "1".to_string(),
            username: "admin".to_string(),
            nickname: "管理员".to_string(),
            email: Some("admin@example.com".to_string()),
        },
        UserInfo {
            id: "2".to_string(),
            username: "user".to_string(),
            nickname: "普通用户".to_string(),
            email: Some("user@example.com".to_string()),
        },
    ];
    
    Ok(Json(ApiResponse::success(users)))
}

#[sa_check_permission("user:delete")]
async fn delete_user(
    Json(req): Json<DeleteUserRequest>,
) -> Result<Json<ApiResponse<String>>, ApiError> {
    tracing::info!("删除用户: {}", req.user_id);
    Ok(Json(ApiResponse::success(format!("用户 {} 已删除", req.user_id))))
}

// ==================== 权限管理接口 ====================

/// 查询用户权限列表
#[sa_check_role("admin")]
async fn list_permissions() -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    // 使用 StpUtil 获取权限
    let admin_perms = StpUtil::get_permissions("admin").await;
    let user_perms = StpUtil::get_permissions("user").await;
    let guest_perms = StpUtil::get_permissions("guest").await;
    
    let data = serde_json::json!({
        "admin": admin_perms,
        "user": user_perms,
        "guest": guest_perms,
    });
    
    Ok(Json(ApiResponse::success(data)))
}

/// 添加权限请求
#[derive(Debug, Deserialize)]
struct AddPermissionRequest {
    user_id: String,
    permission: String,
}

/// 为用户添加权限
#[sa_check_role("admin")]
async fn add_permission(
    Json(req): Json<AddPermissionRequest>,
) -> Result<Json<ApiResponse<String>>, ApiError> {
    // 使用 StpUtil 添加权限
    StpUtil::add_permission(&req.user_id, req.permission.clone())
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    
    tracing::info!("✅ 为用户 {} 添加权限: {}", req.user_id, req.permission);
    Ok(Json(ApiResponse::success(format!(
        "成功为用户 {} 添加权限: {}",
        req.user_id, req.permission
    ))))
}

/// 移除权限请求
#[derive(Debug, Deserialize)]
struct RemovePermissionRequest {
    user_id: String,
    permission: String,
}

/// 移除用户权限
#[sa_check_role("admin")]
async fn remove_permission(
    Json(req): Json<RemovePermissionRequest>,
) -> Result<Json<ApiResponse<String>>, ApiError> {
    // 使用 StpUtil 移除权限
    StpUtil::remove_permission(&req.user_id, &req.permission)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    
    tracing::info!("✅ 移除用户 {} 的权限: {}", req.user_id, req.permission);
    Ok(Json(ApiResponse::success(format!(
        "成功移除用户 {} 的权限: {}",
        req.user_id, req.permission
    ))))
}

/// 查询用户角色列表
#[sa_check_role("admin")]
async fn list_roles() -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    // 使用 StpUtil 获取角色
    let admin_roles = StpUtil::get_roles("admin").await;
    let user_roles = StpUtil::get_roles("user").await;
    let guest_roles = StpUtil::get_roles("guest").await;
    
    let data = serde_json::json!({
        "admin": admin_roles,
        "user": user_roles,
        "guest": guest_roles,
    });
    
    Ok(Json(ApiResponse::success(data)))
}

// ==================== 需要角色的接口 ====================

#[sa_check_role("admin")]
async fn admin_panel() -> Result<Json<ApiResponse<String>>, ApiError> {
    Ok(Json(ApiResponse::success("管理员面板".to_string())))
}

#[sa_check_role("admin")]
async fn admin_stats() -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let stats = serde_json::json!({
        "total_users": 100,
        "active_users": 80,
        "new_users_today": 5,
    });
    
    Ok(Json(ApiResponse::success(stats)))
}

// ==================== 需要多个权限的接口 ====================

#[sa_check_permissions_and("user:read", "user:write")]
async fn manage_user(
    Json(req): Json<ManageUserRequest>,
) -> Result<Json<ApiResponse<String>>, ApiError> {
    tracing::info!("管理用户: {}", req.user_id);
    Ok(Json(ApiResponse::success(format!("用户 {} 管理成功", req.user_id))))
}

// ==================== StpUtil 演示接口 ====================

/// StpUtil 功能演示接口（路径已在 PathAuthConfig::exclude 中放行）
async fn demo_stp_util_api(
    State(_state): State<AppState>,
) -> Result<Json<ApiResponse<String>>, ApiError> {
    tracing::info!("触发 StpUtil 演示...");
    
    match stp_util_demo::demo_stp_util().await {
        Ok(_) => Ok(Json(ApiResponse::success(
            "StpUtil 演示完成，请查看服务器日志".to_string()
        ))),
        Err(e) => Err(ApiError::InternalError(format!("演示失败: {}", e))),
    }
}
