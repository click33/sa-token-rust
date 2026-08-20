// Author: 金书记
//
//! sa-token-macro 基础使用示例
//!
//! In a Web app, public routes must use `PathAuthConfig::exclude`.
//! `#[sa_ignore]` only skips macro-inserted StpUtil checks — it does not skip middleware.
//! 在 Web 应用中，公开路由请用 `PathAuthConfig::exclude`。
//! `#[sa_ignore]` 只跳过宏插入的 StpUtil 检查，不会跳过中间件。

#![allow(clippy::print_stdout, clippy::print_stderr)]

use sa_token_core::SaTokenResult;
use sa_token_macro::*;

// ============ 登录检查示例 ============

#[sa_check_login]
async fn user_info() -> SaTokenResult<String> {
    Ok("User info - requires login".to_string())
}

// ============ 权限检查示例 ============

#[sa_check_permission("user:read")]
async fn get_user(id: u64) -> SaTokenResult<String> {
    Ok(format!("Get user {} - requires user:read permission", id))
}

#[sa_check_permission("user:write")]
async fn update_user(id: u64, name: String) -> SaTokenResult<String> {
    Ok(format!(
        "Update user {} to {} - requires user:write permission",
        id, name
    ))
}

#[sa_check_permission("user:delete")]
async fn delete_user(id: u64) -> SaTokenResult<String> {
    Ok(format!(
        "Delete user {} - requires user:delete permission",
        id
    ))
}

// ============ 角色检查示例 ============

#[sa_check_role("admin")]
async fn admin_panel() -> SaTokenResult<String> {
    Ok("Admin panel - requires admin role".to_string())
}

#[sa_check_role("moderator")]
async fn moderate_content(content_id: u64) -> SaTokenResult<String> {
    Ok(format!(
        "Moderate content {} - requires moderator role",
        content_id
    ))
}

// ============ 多权限检查示例 ============

#[sa_check_permissions_and("user:read", "user:write")]
async fn manage_user() -> SaTokenResult<String> {
    Ok("Manage user - requires both user:read AND user:write permissions".to_string())
}

#[sa_check_permissions_or("admin:all", "super:all")]
async fn super_admin_action() -> SaTokenResult<String> {
    Ok("Super admin action - requires admin:all OR super:all permission".to_string())
}

// ============ 多角色检查示例 ============

#[sa_check_roles_and("admin", "super")]
async fn super_admin_panel() -> SaTokenResult<String> {
    Ok("Super admin panel - requires both admin AND super roles".to_string())
}

#[sa_check_roles_or("admin", "moderator")]
async fn moderate_or_admin() -> SaTokenResult<String> {
    Ok("Moderate or admin - requires admin OR moderator role".to_string())
}

// ============ 封禁 / 二级认证 / 组合 OR ============

#[sa_check_safe]
async fn transfer_money() -> SaTokenResult<String> {
    Ok("Transfer - requires secondary auth".to_string())
}

#[sa_check_safe("pay")]
async fn pay_order() -> SaTokenResult<String> {
    Ok("Pay - requires pay secondary auth".to_string())
}

#[sa_check_disable]
async fn active_account_action() -> SaTokenResult<String> {
    Ok("Active account only".to_string())
}

#[sa_check_disable("login", level = 1)]
async fn not_banned_login() -> SaTokenResult<String> {
    Ok("Not banned for login service".to_string())
}

#[sa_check_or(permission = "user:read", role = "admin")]
async fn read_or_admin() -> SaTokenResult<String> {
    Ok("Read or admin role".to_string())
}

// ============ #[sa_ignore] 示例（无 HTTP 层时可保留；Web 公开路径请用 exclude）============

#[sa_ignore]
async fn public_api() -> String {
    "Public API - no authentication required".to_string()
}

#[sa_ignore]
async fn health_check() -> String {
    "OK - health check doesn't need auth".to_string()
}

// ============ 结构体级别的 #[sa_ignore]（无 HTTP 层）============

#[sa_ignore]
struct PublicController;

impl PublicController {
    async fn home() -> String {
        "Home page - public access".to_string()
    }

    #[allow(dead_code)]
    async fn about() -> String {
        "About page - public access".to_string()
    }
}

// ============ impl块级别的 #[sa_ignore]（无 HTTP 层）============

struct ApiController;

#[sa_ignore]
impl ApiController {
    async fn version() -> String {
        "v1.0.0 - version API is public".to_string()
    }

    #[allow(dead_code)]
    async fn status() -> String {
        "running - status API is public".to_string()
    }
}

// ============ 混合使用示例 ============

struct UserController;

impl UserController {
    // 公开接口
    #[sa_ignore]
    async fn register(username: String) -> String {
        format!("Register user: {} - public", username)
    }

    // 需要登录
    #[sa_check_login]
    async fn profile() -> SaTokenResult<String> {
        Ok("User profile - requires login".to_string())
    }

    // 需要特定权限
    #[sa_check_permission("user:update_profile")]
    async fn update_profile(data: String) -> SaTokenResult<String> {
        Ok(format!("Update profile: {} - requires permission", data))
    }

    // 需要管理员角色
    #[sa_check_role("admin")]
    async fn list_all_users() -> SaTokenResult<String> {
        Ok("List all users - requires admin role".to_string())
    }
}

#[tokio::main]
async fn main() {
    println!("=== sa-token-macro 示例 ===\n");

    // 注意：以下带认证检查的函数在未初始化 SaTokenManager 时会返回 Err
    // 实际使用时需要先调用 StpUtil::init_manager() 并通过中间件设置上下文

    println!("1. 公开API（#[sa_ignore]，无 HTTP 层）:");
    println!("   {}", public_api().await);
    println!("   {}", health_check().await);

    println!("\n2. 控制器示例:");
    println!("   {}", PublicController::home().await);
    println!("   {}", ApiController::version().await);
    println!("   {}", UserController::register("Bob".to_string()).await);

    println!("\n3. 需要登录的接口（未设置上下文，预期返回 Err）:");
    println!("   user_info: {:?}", user_info().await);
    println!("   get_user: {:?}", get_user(123).await);
    println!("   admin_panel: {:?}", admin_panel().await);

    println!("\n注意：带认证宏的函数需要配合中间件使用，单独调用会因为缺少上下文而返回错误。");
}
