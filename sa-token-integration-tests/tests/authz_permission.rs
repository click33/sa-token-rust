//! P0: Permission / Role checking integration tests.
//!
//! Covers exact-match, wildcard (`*`, `**`), AND/OR logic, and failure paths.
//! 测试共享全局 SaStorage，使用 serial 避免并行写入同一 login_id 产生竞态。

mod common;

use common::setup;
use sa_token_core::{SaTokenError, StpUtil};
use serial_test::serial;

// ── Helpers ────────────────────────────────────────────────────────────────

async fn setup_user_with_perms(login_id: &str, permissions: Vec<&str>) {
    // Ensure StpUtil is initialized
    let _ = setup::shared_manager();
    let perms: Vec<String> = permissions.into_iter().map(String::from).collect();
    StpUtil::set_permissions(login_id, perms).await.unwrap();
}

async fn setup_user_with_roles(login_id: &str, roles: Vec<&str>) {
    let _ = setup::shared_manager();
    let r: Vec<String> = roles.into_iter().map(String::from).collect();
    StpUtil::set_roles(login_id, r).await.unwrap();
}

// ── Success cases: exact match ─────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn test_set_and_check_exact_permission() {
    setup_user_with_perms("user_a", vec!["user:list"]).await;
    assert!(StpUtil::has_permission("user_a", "user:list").await);
}

#[tokio::test]
#[serial]
async fn test_set_and_check_exact_role() {
    setup_user_with_roles("user_a", vec!["admin"]).await;
    assert!(StpUtil::has_role("user_a", "admin").await);
}

#[tokio::test]
#[serial]
async fn test_get_permissions_returns_vec() {
    setup_user_with_perms("user_a", vec!["user:list", "user:add"]).await;
    let perms = StpUtil::get_permissions("user_a").await;
    assert!(perms.contains(&"user:list".to_string()));
    assert!(perms.contains(&"user:add".to_string()));
}

#[tokio::test]
#[serial]
async fn test_get_roles_returns_vec() {
    setup_user_with_roles("user_a", vec!["admin", "user"]).await;
    let roles = StpUtil::get_roles("user_a").await;
    assert!(roles.contains(&"admin".to_string()));
    assert!(roles.contains(&"user".to_string()));
}

#[tokio::test]
#[serial]
async fn test_clear_permissions() {
    setup_user_with_perms("user_a", vec!["user:list"]).await;
    StpUtil::clear_permissions("user_a").await.unwrap();
    assert!(!StpUtil::has_permission("user_a", "user:list").await);
}

#[tokio::test]
#[serial]
async fn test_clear_roles() {
    setup_user_with_roles("user_a", vec!["admin"]).await;
    StpUtil::clear_roles("user_a").await.unwrap();
    assert!(!StpUtil::has_role("user_a", "admin").await);
}

#[tokio::test]
#[serial]
async fn test_add_individual_permission() {
    let _mgr = setup::shared_manager();
    StpUtil::add_permission("user_b", "api:list").await.unwrap();
    assert!(StpUtil::has_permission("user_b", "api:list").await);
    // Adding again should not duplicate
    StpUtil::add_permission("user_b", "api:list").await.unwrap();
    let perms = StpUtil::get_permissions("user_b").await;
    assert_eq!(perms.iter().filter(|p| *p == "api:list").count(), 1);
}

#[tokio::test]
#[serial]
async fn test_remove_permission() {
    setup_user_with_perms("user_c", vec!["user:list", "user:add"]).await;
    StpUtil::remove_permission("user_c", "user:list")
        .await
        .unwrap();
    assert!(!StpUtil::has_permission("user_c", "user:list").await);
    assert!(StpUtil::has_permission("user_c", "user:add").await);
}

// ── Success cases: wildcard matching ───────────────────────────────────────

#[tokio::test]
#[serial]
async fn test_permission_wildcard_single_star_prefix() {
    setup_user_with_perms("user_d", vec!["user:*"]).await;
    assert!(StpUtil::has_permission("user_d", "user:list").await);
    assert!(StpUtil::has_permission("user_d", "user:delete").await);
    assert!(StpUtil::has_permission("user_d", "user:add").await);
    // "user:*" should NOT match "admin:list"
    assert!(!StpUtil::has_permission("user_d", "admin:list").await);
}

#[tokio::test]
#[serial]
async fn test_permission_wildcard_nested_prefix() {
    // B2-14：`*` 只匹配单段；跨段需 `**`。
    // B2-14: `*` matches one segment only; use `**` for nested paths.
    setup_user_with_perms("user_d", vec!["admin:*"]).await;
    // 单段：匹配 | single segment: match
    assert!(StpUtil::has_permission("user_d", "admin:settings").await);
    // 多段：单星不匹配 | multi-segment: single-star must not match
    assert!(!StpUtil::has_permission("user_d", "admin:user:delete").await);
    assert!(!StpUtil::has_permission("user_d", "admin:user:list").await);
    // 跨命名空间 | cross-namespace
    assert!(!StpUtil::has_permission("user_d", "other:admin").await);

    // 双星通配可覆盖嵌套路径 | double-star covers nested paths
    setup_user_with_perms("user_d2", vec!["admin:**"]).await;
    assert!(StpUtil::has_permission("user_d2", "admin:settings").await);
    assert!(StpUtil::has_permission("user_d2", "admin:user:delete").await);
    assert!(StpUtil::has_permission("user_d2", "admin:user:list").await);
    assert!(!StpUtil::has_permission("user_d2", "other:admin").await);
}

#[tokio::test]
#[serial]
async fn test_permission_matches_among_multiple() {
    setup_user_with_perms("user_d", vec!["other:perm", "user:*", "another:perm"]).await;
    assert!(StpUtil::has_permission("user_d", "user:anything").await);
}

// ── Success cases: AND / OR logic ────────────────────────────────────────

#[tokio::test]
#[serial]
async fn test_has_permissions_and_true() {
    setup_user_with_perms("user_e", vec!["user:read", "user:write", "user:delete"]).await;
    assert!(StpUtil::has_permissions_and("user_e", &["user:read", "user:write"]).await);
}

#[tokio::test]
#[serial]
async fn test_has_permissions_and_false_when_missing_one() {
    setup_user_with_perms("user_e", vec!["user:read"]).await;
    assert!(!StpUtil::has_permissions_and("user_e", &["user:read", "user:delete"]).await);
}

#[tokio::test]
#[serial]
async fn test_has_permissions_or_true() {
    setup_user_with_perms("user_f", vec!["user:read"]).await;
    assert!(StpUtil::has_permissions_or("user_f", &["user:read", "user:delete"]).await);
}

#[tokio::test]
#[serial]
async fn test_has_permissions_or_false_when_none_match() {
    setup_user_with_perms("user_f", vec!["user:read"]).await;
    assert!(!StpUtil::has_permissions_or("user_f", &["admin:panel", "user:delete"]).await);
}

#[tokio::test]
#[serial]
async fn test_has_roles_and() {
    setup_user_with_roles("user_g", vec!["admin", "moderator"]).await;
    assert!(StpUtil::has_roles_and("user_g", &["admin", "moderator"]).await);
}

#[tokio::test]
#[serial]
async fn test_has_roles_or() {
    setup_user_with_roles("user_g", vec!["user"]).await;
    assert!(StpUtil::has_roles_or("user_g", &["admin", "user"]).await);
}

#[tokio::test]
#[serial]
async fn test_check_permission_success() {
    setup_user_with_perms("user_h", vec!["user:delete"]).await;
    let result = StpUtil::check_permission("user_h", "user:delete").await;
    assert!(result.is_ok());
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn test_has_permission_not_set_returns_false() {
    let _mgr = setup::shared_manager();
    assert!(!StpUtil::has_permission("unconfigured_user", "user:list").await);
}

#[tokio::test]
#[serial]
async fn test_has_role_not_set_returns_false() {
    let _mgr = setup::shared_manager();
    assert!(!StpUtil::has_role("unconfigured_user", "admin").await);
}

#[tokio::test]
#[serial]
async fn test_get_permissions_not_set_returns_empty() {
    let _mgr = setup::shared_manager();
    let perms = StpUtil::get_permissions("unconfigured_user2").await;
    assert!(perms.is_empty());
}

#[tokio::test]
#[serial]
async fn test_get_roles_not_set_returns_empty() {
    let _mgr = setup::shared_manager();
    let roles = StpUtil::get_roles("unconfigured_user2").await;
    assert!(roles.is_empty());
}

#[tokio::test]
#[serial]
async fn test_wildcard_does_not_cross_namespaces() {
    setup_user_with_perms("user_i", vec!["user:*"]).await;
    assert!(!StpUtil::has_permission("user_i", "admin:user:delete").await);
}

#[tokio::test]
#[serial]
async fn test_check_permission_denied_returns_error() {
    setup_user_with_perms("user_j", vec!["user:read"]).await;
    let result = StpUtil::check_permission("user_j", "user:delete").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::PermissionDeniedDetail(ref msg) if msg == "user:delete"
    ));
}

#[tokio::test]
#[serial]
async fn test_numeric_login_id_permissions() {
    let _mgr = setup::shared_manager();
    StpUtil::login(20001).await.expect("numeric login");
    setup_user_with_perms("20001", vec!["api:access"]).await;
    assert!(StpUtil::has_permission(20001, "api:access").await);
    setup_user_with_perms("20001", vec!["api:*"]).await;
    assert!(StpUtil::has_permission(20001, "api:read").await);
}
