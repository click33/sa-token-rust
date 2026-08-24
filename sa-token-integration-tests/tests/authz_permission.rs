//! P0: Permission / Role checking — unique login_id，失败匹配错误变体。

mod common;

use common::setup;
use sa_token_core::{SaTokenError, StpUtil};
use serial_test::serial;

async fn setup_user_with_perms(login_id: &str, permissions: Vec<&str>) {
    let _mgr = setup::shared_manager();
    let perms: Vec<String> = permissions.into_iter().map(String::from).collect();
    StpUtil::set_permissions(login_id, perms)
        .await
        .expect("set_permissions");
}

async fn setup_user_with_roles(login_id: &str, roles: Vec<&str>) {
    let _mgr = setup::shared_manager();
    let r: Vec<String> = roles.into_iter().map(String::from).collect();
    StpUtil::set_roles(login_id, r).await.expect("set_roles");
}

#[tokio::test]
#[serial]
async fn test_set_and_check_exact_permission() {
    let id = setup::unique_login_id("perm");
    setup_user_with_perms(&id, vec!["user:list"]).await;
    assert!(StpUtil::has_permission(&id, "user:list").await);
}

#[tokio::test]
#[serial]
async fn test_set_and_check_exact_role() {
    let id = setup::unique_login_id("role");
    setup_user_with_roles(&id, vec!["admin"]).await;
    assert!(StpUtil::has_role(&id, "admin").await);
}

#[tokio::test]
#[serial]
async fn test_clear_permissions() {
    let id = setup::unique_login_id("clr_p");
    setup_user_with_perms(&id, vec!["user:list"]).await;
    StpUtil::clear_permissions(&id).await.expect("clear");
    assert!(!StpUtil::has_permission(&id, "user:list").await);
}

#[tokio::test]
#[serial]
async fn test_clear_roles() {
    let id = setup::unique_login_id("clr_r");
    setup_user_with_roles(&id, vec!["admin"]).await;
    StpUtil::clear_roles(&id).await.expect("clear");
    assert!(!StpUtil::has_role(&id, "admin").await);
}

#[tokio::test]
#[serial]
async fn test_add_permission_no_duplicate() {
    let id = setup::unique_login_id("add_p");
    let _mgr = setup::shared_manager();
    StpUtil::add_permission(&id, "api:list").await.expect("add");
    StpUtil::add_permission(&id, "api:list").await.expect("add2");
    let perms = StpUtil::get_permissions(&id).await;
    assert_eq!(perms.iter().filter(|p| *p == "api:list").count(), 1);
}

#[tokio::test]
#[serial]
async fn test_remove_permission() {
    let id = setup::unique_login_id("rm_p");
    setup_user_with_perms(&id, vec!["user:list", "user:add"]).await;
    StpUtil::remove_permission(&id, "user:list")
        .await
        .expect("remove");
    assert!(!StpUtil::has_permission(&id, "user:list").await);
    assert!(StpUtil::has_permission(&id, "user:add").await);
}

#[tokio::test]
#[serial]
async fn test_permission_wildcard_single_star() {
    let id = setup::unique_login_id("wild");
    setup_user_with_perms(&id, vec!["user:*"]).await;
    assert!(StpUtil::has_permission(&id, "user:list").await);
    assert!(!StpUtil::has_permission(&id, "admin:list").await);
}

#[tokio::test]
#[serial]
async fn test_permission_wildcard_star_vs_double_star() {
    let id = setup::unique_login_id("nest");
    setup_user_with_perms(&id, vec!["admin:*"]).await;
    assert!(StpUtil::has_permission(&id, "admin:settings").await);
    assert!(!StpUtil::has_permission(&id, "admin:user:delete").await);

    let id2 = setup::unique_login_id("nest2");
    setup_user_with_perms(&id2, vec!["admin:**"]).await;
    assert!(StpUtil::has_permission(&id2, "admin:user:delete").await);
    assert!(!StpUtil::has_permission(&id2, "other:admin").await);
}

#[tokio::test]
#[serial]
async fn test_has_permissions_and_or() {
    let id = setup::unique_login_id("andor");
    setup_user_with_perms(&id, vec!["user:read", "user:write"]).await;
    assert!(StpUtil::has_permissions_and(&id, &["user:read", "user:write"]).await);
    assert!(!StpUtil::has_permissions_and(&id, &["user:read", "user:delete"]).await);
    assert!(StpUtil::has_permissions_or(&id, &["user:read", "user:delete"]).await);
    assert!(!StpUtil::has_permissions_or(&id, &["admin:panel", "user:delete"]).await);
}

#[tokio::test]
#[serial]
async fn test_empty_permissions_and_or_contract() {
    let id = setup::unique_login_id("empty");
    setup_user_with_perms(&id, vec!["user:read"]).await;
    assert!(StpUtil::has_permissions_and(&id, &[]).await);
    assert!(!StpUtil::has_permissions_or(&id, &[]).await);
}

#[tokio::test]
#[serial]
async fn test_check_permission_success_and_denied() {
    let id = setup::unique_login_id("chk");
    setup_user_with_perms(&id, vec!["user:delete"]).await;
    StpUtil::check_permission(&id, "user:delete")
        .await
        .expect("ok");
    let denied = StpUtil::check_permission(&id, "user:read").await;
    assert!(matches!(
        denied,
        Err(SaTokenError::PermissionDeniedDetail(ref msg)) if msg == "user:read"
    ));
}

#[tokio::test]
#[serial]
async fn test_has_permission_not_set_returns_false() {
    let _mgr = setup::shared_manager();
    let id = setup::unique_login_id("none");
    assert!(!StpUtil::has_permission(&id, "user:list").await);
    assert!(StpUtil::get_permissions(&id).await.is_empty());
}
