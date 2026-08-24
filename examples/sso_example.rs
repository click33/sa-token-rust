//! # SSO 单点登录示例 | SSO Single Sign-On Example
//!
//! 本示例演示 sa-token-rust 的完整 SSO 功能
//! This example demonstrates the complete SSO functionality of sa-token-rust
//!
//! ## 示例场景 | Example Scenarios
//!
//! 1. 用户在应用1登录 | User logs in at App1
//! 2. 用户访问应用2（SSO 生效）| User accesses App2 (SSO in action)
//! 3. 用户访问应用3 | User accesses App3
//! 4. 检查 SSO 会话 | Check SSO session
//! 5. 统一登出 | Unified logout
//! 6. 票据过期测试 | Ticket expiration test
//! 7. 跨域支持 | Cross-domain support
//! 8. URL 生成 | URL generation
//! 9. 服务匹配保护 | Service mismatch protection
//! 10. 清理过期票据 | Cleanup expired tickets

#![allow(clippy::print_stdout, clippy::print_stderr)]

use sa_token_core::{SaTokenConfig, SsoClient, SsoConfig, SsoManager, SsoServer};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== sa-token SSO Example ===\n");

    // ========================================
    // 初始化 sa-token | Initialize sa-token
    // ========================================
    let storage = Arc::new(MemoryStorage::new());

    // 创建 SaTokenManager | Create SaTokenManager
    let manager = SaTokenConfig::builder()
        .storage(storage.clone())
        .timeout(7200)  // 2小时 Token 超时 | 2-hour Token timeout
        .build();

    // ========================================
    // 步骤 1: SSO 配置与服务端 | Step 1: SSO Config and Server
    // ========================================
    println!("Step 1: Create SSO Server");
    let manager = Arc::new(manager);

    let sso_config = SsoConfig::builder()
        .server_url("http://sso.example.com/auth") // SSO 服务端 URL | SSO Server URL
        .ticket_timeout(300) // 票据超时时间 | Ticket timeout
        .allow_cross_domain(true) // 允许跨域 | Allow cross-domain
        .add_allowed_origin("http://app1.example.com".to_string()) // 白名单 | Whitelist
        .add_allowed_origin("http://app2.example.com".to_string())
        .add_allowed_origin("http://app3.example.com".to_string())
        .build();

    // 创建 SSO 服务端（注入白名单）| Create SSO Server with origin whitelist
    let sso_server = Arc::new(
        SsoServer::new(manager.clone())
            .with_config(&sso_config)
            .with_ticket_timeout(300), // 300秒 = 5分钟 | 300s = 5min
    );
    println!("SSO Server created with 5-minute ticket timeout\n");

    // ========================================
    // 步骤 2: 创建 SSO 客户端 | Step 2: Create SSO Clients
    // ========================================
    println!("Step 2: Create SSO Clients");
    let ticket_store =
        sa_token_core::SsoTicketStore::new(manager.dao().clone(), sso_config.ticket_timeout);
    let local_checker = Arc::new(sa_token_core::LocalTicketChecker {
        store: ticket_store,
    });

    // 客户端 1 - 应用1 | Client 1 - App1
    let client1 = Arc::new(
        SsoClient::new(
            manager.clone(),
            "http://sso.example.com/auth".to_string(), // SSO 服务端地址 | SSO Server URL
            "http://app1.example.com".to_string(),     // 当前应用地址 | Current app URL
        )
        .with_ticket_checker(local_checker.clone()),
    );

    // 客户端 2 - 应用2 | Client 2 - App2
    let client2 = Arc::new(
        SsoClient::new(
            manager.clone(),
            "http://sso.example.com/auth".to_string(),
            "http://app2.example.com".to_string(),
        )
        .with_ticket_checker(local_checker.clone()),
    );

    // 客户端 3 - 应用3 | Client 3 - App3
    let client3 = Arc::new(
        SsoClient::new(
            manager.clone(),
            "http://sso.example.com/auth".to_string(),
            "http://app3.example.com".to_string(),
        )
        .with_ticket_checker(local_checker),
    );
    println!("Created 3 SSO clients\n");

    // ========================================
    // 步骤 3: SSO 管理器 | Step 3: SSO Manager
    // ========================================
    println!("Step 3: SSO Manager");
    let sso_manager = SsoManager::new(sso_config)
        .with_server(sso_server.clone())
        .with_client(client1.clone());
    println!("SSO Manager configured\n");
    println!("{}", "=".repeat(60));

    // ========================================
    // 场景 1: 用户在应用1登录 | Scenario 1: User logs in at App1
    // ========================================
    println!("\nScenario 1: User logs in at App1");
    println!("{}", "-".repeat(60));

    let user_id = "user_123";

    // 1. 用户在 SSO Server 登录 | User logs in at SSO Server
    let ticket1 = sso_server
        .login(user_id.to_string(), "http://app1.example.com".to_string())
        .await?;

    println!("Generated ticket for App1:");
    println!("  Ticket ID: {}", ticket1.ticket_id);
    println!("  Service: {}", ticket1.service);
    println!("  Login ID: {}", ticket1.login_id);
    println!("  Expires: {}", ticket1.expire_time);

    // 2. 验证票据 | Validate ticket
    let login_id1 = sso_server
        .validate_ticket(&ticket1.ticket_id, "http://app1.example.com")
        .await?;

    println!("Ticket validated successfully: {}", login_id1);

    // 3. 创建本地会话 | Create local session
    let token1 = client1.login_by_ticket(login_id1.clone()).await?;
    println!("App1 local session created: {}", token1);

    // ========================================
    // 场景 2: 用户访问应用2（SSO 生效）| Scenario 2: User accesses App2 (SSO in action)
    // ========================================
    println!("\nScenario 2: User accesses App2 (SSO in action)");
    println!("{}", "-".repeat(60));

    // 检查用户是否已登录 SSO Server | Check if user is already logged in SSO Server
    let is_logged_in = sso_server.is_logged_in(user_id).await;
    println!("User already logged in SSO Server: {}", is_logged_in);

    // 直接创建票据，无需再次登录！| Directly create ticket, no re-login required!
    let ticket2 = sso_server
        .create_ticket(user_id.to_string(), "http://app2.example.com".to_string())
        .await?;

    println!("Generated ticket for App2:");
    println!("  Ticket ID: {}", ticket2.ticket_id);

    // 验证票据并创建本地会话 | Validate ticket and create local session
    let login_id2 = sso_server
        .validate_ticket(&ticket2.ticket_id, "http://app2.example.com")
        .await?;

    let token2 = client2.login_by_ticket(login_id2.clone()).await?;
    println!("App2 local session created: {}", token2);

    // ========================================
    // 场景 3: 用户访问应用3 | Scenario 3: User accesses App3
    // ========================================
    println!("\nScenario 3: User accesses App3");
    println!("{}", "-".repeat(60));

    let ticket3 = sso_server
        .create_ticket(user_id.to_string(), "http://app3.example.com".to_string())
        .await?;

    let login_id3 = sso_server
        .validate_ticket(&ticket3.ticket_id, "http://app3.example.com")
        .await?;

    let token3 = client3.login_by_ticket(login_id3.clone()).await?;
    println!("App3 local session created: {}", token3);

    println!("\nScenario 4: Check SSO Session");
    println!("{}", "-".repeat(60));

    let active_clients = sso_server.get_active_clients(user_id).await;
    println!("User logged into {} applications:", active_clients.len());
    for (i, client) in active_clients.iter().enumerate() {
        println!("  {}. {}", i + 1, client);
    }

    let session = sso_server.get_session(user_id).await;
    if let Some(s) = session {
        println!("SSO Session details:");
        println!("  Login ID: {}", s.login_id);
        println!("  Active clients: {}", s.clients.len());
        println!("  Created: {}", s.create_time);
        println!("  Last active: {}", s.last_active_time);
    }

    println!("\nScenario 5: Unified Logout");
    println!("{}", "-".repeat(60));

    let logged_out_clients = sso_server.logout(user_id).await?;
    println!("User logged out from SSO Server");
    println!("Notifying {} clients to logout:", logged_out_clients.len());
    for (i, client_url) in logged_out_clients.iter().enumerate() {
        println!("  {}. {} - clearing local session", i + 1, client_url);
    }

    client1.handle_logout(user_id).await?;
    client2.handle_logout(user_id).await?;
    client3.handle_logout(user_id).await?;
    println!("All local sessions cleared");

    let is_still_logged_in = sso_server.check_session(user_id).await;
    println!("User still logged in: {}", is_still_logged_in);

    println!("\nScenario 6: Ticket Expiration");
    println!("{}", "-".repeat(60));

    let expired_ticket = sso_server
        .create_ticket(
            "user_456".to_string(),
            "http://app1.example.com".to_string(),
        )
        .await?;

    println!("Created ticket: {}", expired_ticket.ticket_id);
    println!("Ticket is valid: {}", expired_ticket.is_valid());

    match sso_server
        .validate_ticket(&expired_ticket.ticket_id, "http://app1.example.com")
        .await
    {
        Ok(id) => println!("Ticket validated: {}", id),
        Err(e) => println!("Ticket validation failed: {}", e),
    }

    match sso_server
        .validate_ticket(&expired_ticket.ticket_id, "http://app1.example.com")
        .await
    {
        Ok(id) => println!("Second validation: {}", id),
        Err(e) => println!("Second validation failed (ticket already used): {}", e),
    }

    println!("\nScenario 7: Cross-Domain Support");
    println!("{}", "-".repeat(60));

    let origins = vec![
        "http://app1.example.com",
        "http://app2.example.com",
        "http://evil.com",
        "http://app3.example.com",
    ];

    for origin in origins {
        let allowed = sso_manager.is_allowed_origin(origin);
        println!(
            "Origin '{}': {}",
            origin,
            if allowed { "✓ Allowed" } else { "✗ Denied" }
        );
    }

    println!("\nScenario 8: Client URL Generation");
    println!("{}", "-".repeat(60));

    println!("Client1 Login URL: {}", client1.get_login_url());
    println!("Client1 Logout URL: {}", client1.get_logout_url());
    println!("Client2 Login URL: {}", client2.get_login_url());
    println!("Client3 Login URL: {}", client3.get_login_url());

    println!("\nScenario 9: Service Mismatch Protection");
    println!("{}", "-".repeat(60));

    let ticket_app1 = sso_server
        .create_ticket(
            "user_789".to_string(),
            "http://app1.example.com".to_string(),
        )
        .await?;

    match sso_server
        .validate_ticket(&ticket_app1.ticket_id, "http://app2.example.com")
        .await
    {
        Ok(_) => println!("Validation succeeded (unexpected)"),
        Err(e) => println!("Service mismatch detected: {}", e),
    }

    println!("\nScenario 10: Cleanup Expired Tickets");
    println!("{}", "-".repeat(60));

    for i in 1..=5 {
        let _ = sso_server
            .create_ticket(
                format!("temp_user_{}", i),
                "http://app1.example.com".to_string(),
            )
            .await;
    }

    println!("Created 5 temporary tickets");
    sso_server.cleanup_expired_tickets().await;
    println!("Cleanup completed - all valid tickets remain");

    println!("\n{}", "=".repeat(60));
    println!("SSO Example completed successfully!");
    println!("Key Features Demonstrated:");
    println!("  ✓ Single Sign-On across multiple applications");
    println!("  ✓ Ticket-based authentication");
    println!("  ✓ Unified logout");
    println!("  ✓ Cross-domain support with origin validation");
    println!("  ✓ Ticket expiration and reuse prevention");
    println!("  ✓ Service mismatch protection");
    println!("  ✓ Session management");

    Ok(())
}
