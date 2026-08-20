//! WebSocket 认证与在线用户管理示例
//!
//! 演示 WebSocket 认证和在线用户追踪功能
//!
//! ## 导入方式
//!
//! ### 方式1: 独立使用核心库（本示例）
//! ```ignore
//! use sa_token_core::{WsAuthManager, OnlineManager, OnlineUser, ...};
//! ```
//!
//! ### 方式2: 使用 Web 框架插件（推荐）
//! ```toml
//! [dependencies]
//! sa-token-plugin-axum = "0.1.3"
//! ```
//! ```ignore
//! use sa_token_plugin_axum::*;  // WebSocket 和在线用户功能已重新导出！
//! ```

#![allow(clippy::print_stdout, clippy::print_stderr)]

use sa_token_core::{
    InMemoryPusher, OnlineManager, OnlineUser, SaTokenConfig, SaTokenManager, WsAuthManager,
};
use sa_token_storage_memory::MemoryStorage;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("========================================");
    println!(
        "WebSocket 认证与在线用户管理示例 | WebSocket Authentication & Online User Management Example"
    );
    println!("========================================\n");

    let config = SaTokenConfig::default();
    let storage = Arc::new(MemoryStorage::new());

    let online_manager = Arc::new(OnlineManager::new());
    let pusher = Arc::new(InMemoryPusher::new());
    online_manager.register_pusher(pusher.clone()).await;

    let manager_with_online =
        SaTokenManager::new(storage, config).with_online_manager(online_manager.clone());

    let ws_manager = WsAuthManager::new(Arc::new(manager_with_online.clone()));

    println!("1. User Login and WebSocket Authentication");
    let token1 = manager_with_online.login("user1").await?;
    println!("   User1 logged in, token: {}", token1.as_str());

    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        format!("Bearer {}", token1.as_str()),
    );

    let ws_auth = ws_manager.authenticate(&headers, &HashMap::new()).await?;
    println!("   WebSocket authenticated: {}", ws_auth.login_id);
    println!("   Session ID: {}\n", ws_auth.session_id);

    println!("2. Mark User as Online");
    let online_user = OnlineUser {
        login_type: "login".to_string(),
        login_id: ws_auth.login_id.clone(),
        token: ws_auth.token.clone(),
        device: "web".to_string(),
        connect_time: ws_auth.connect_time,
        last_activity: ws_auth.connect_time,
        metadata: HashMap::new(),
    };
    online_manager.mark_online(online_user).await?;
    println!("   User1 marked as online");
    println!(
        "   Online count: {}\n",
        online_manager.get_online_count().await?
    );

    println!("3. Login Multiple Users");
    for i in 2..=5 {
        let token = manager_with_online.login(format!("user{}", i)).await?;
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", token.as_str()),
        );

        let ws_auth = ws_manager.authenticate(&headers, &HashMap::new()).await?;

        let online_user = OnlineUser {
            login_type: "login".to_string(),
            login_id: ws_auth.login_id.clone(),
            token: ws_auth.token.clone(),
            device: "mobile".to_string(),
            connect_time: ws_auth.connect_time,
            last_activity: ws_auth.connect_time,
            metadata: HashMap::new(),
        };
        online_manager.mark_online(online_user).await?;
        println!("   User{} online", i);
    }
    println!(
        "   Total online: {}\n",
        online_manager.get_online_count().await?
    );

    println!("4. Get Online Users");
    let online_users = online_manager.get_online_users().await?;
    println!("   Online users: {:?}\n", online_users);

    println!("5. Push Message to Single User");
    online_manager
        .push_to_user("user1", "Hello User1!".to_string())
        .await?;
    let messages = pusher.get_messages("user1").await;
    println!("   User1 received {} message(s)", messages.len());
    if let Some(msg) = messages.first() {
        println!("   Content: {}\n", msg.content);
    }

    println!("6. Broadcast Message to All Users");
    online_manager
        .broadcast("System announcement!".to_string())
        .await?;
    for i in 1..=5 {
        let messages = pusher.get_messages(&format!("user{}", i)).await;
        println!("   User{} total messages: {}", i, messages.len());
    }
    println!();

    println!("7. Kick Out User with Notification");
    manager_with_online.kick_out("login", "user3").await?;
    println!("   User3 kicked out");

    let is_online = online_manager.is_online("user3").await?;
    println!("   User3 online status: {}", is_online);

    let kick_messages = pusher.get_messages("user3").await;
    let kick_msg = kick_messages
        .iter()
        .find(|m| matches!(m.message_type, sa_token_core::MessageType::KickOut));
    if let Some(msg) = kick_msg {
        println!("   Kick notification: {}\n", msg.content);
    }

    println!("8. Update User Activity");
    online_manager
        .update_activity("user1", token1.as_str())
        .await?;
    let sessions = online_manager.get_user_sessions("user1").await?;
    if let Some(session) = sessions.first() {
        println!("   User1 last activity: {}\n", session.last_activity);
    }

    println!("9. Mark User Offline");
    let user2_token = manager_with_online.login("user2").await?;
    online_manager
        .mark_offline("user2", user2_token.as_str())
        .await?;
    println!("   User2 marked offline");
    println!(
        "   Total online: {}\n",
        online_manager.get_online_count().await?
    );

    println!("10. Token Verification from Query Parameter");
    let token5 = manager_with_online.login("user5").await?;
    let mut query = HashMap::new();
    query.insert("token".to_string(), token5.as_str().to_string());

    let ws_auth = ws_manager.authenticate(&HashMap::new(), &query).await?;
    println!(
        "   User5 authenticated via query param: {}\n",
        ws_auth.login_id
    );

    println!("=== Example Completed Successfully ===");

    Ok(())
}
