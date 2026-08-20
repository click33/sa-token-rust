// Author: 金书记
//
//! StpUtil 使用示例 - 完整功能展示
//! StpUtil Usage Example - Complete Features Demo
//!
//! 演示如何使用 StpUtil 工具类的所有功能
//! Demonstrates all features of the StpUtil utility class
//!
//! ## 导入方式 | Import Methods
//!
//! ### 方式1: 独立使用核心库（本示例）| Method 1: Use Core Library (This Example)
//! ```ignore
//! use sa_token_core::{StpUtil, SaTokenManager, SaTokenConfig};
//! use sa_token_storage_memory::MemoryStorage;
//! ```
//!
//! ### 方式2: 使用 Web 框架插件（推荐）| Method 2: Use Web Framework Plugin (Recommended)
//! ```toml
//! [dependencies]
//! sa-token-plugin-axum = "0.1.3"  // 一站式包 | All-in-one package
//! ```
//! ```ignore
//! use sa_token_plugin_axum::*;  // StpUtil 和所有功能已重新导出！| StpUtil and all features re-exported!
//! ```

#![allow(clippy::print_stdout, clippy::print_stderr)]

use async_trait::async_trait;
use sa_token_core::{
    SaTokenConfig, SaTokenListener, SaTokenManager, StpUtil,
    config::TokenStyle,
    token::{TokenInfo, TokenValue},
};
use sa_token_storage_memory::MemoryStorage;
use serde_json::json;
use std::sync::Arc;

/// 简单的事件监听器用于演示 | Simple Event Listener for Demo
struct DemoListener;

#[async_trait]
impl SaTokenListener for DemoListener {
    async fn on_login(&self, login_id: &str, _token: &str, _login_type: &str) {
        println!(
            "   🎧 [事件监听 | Event] 用户登录 | User Login: {}",
            login_id
        );
    }

    async fn on_logout(&self, login_id: &str, _token: &str, _login_type: &str) {
        println!(
            "   🎧 [事件监听 | Event] 用户登出 | User Logout: {}",
            login_id
        );
    }

    async fn on_kick_out(&self, login_id: &str, _token: &str, _login_type: &str) {
        println!(
            "   🎧 [事件监听 | Event] 用户被踢出 | User Kicked Out: {}",
            login_id
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║  🚀 StpUtil 完整功能示例 | StpUtil Complete Features Demo  ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // ========================================
    // 步骤 1: 初始化（现代化方式）| Step 1: Initialize (Modern Way)
    // ========================================
    println!("📦 步骤 1: 初始化 sa-token | Step 1: Initialize sa-token");
    println!("{}", "─".repeat(60));

    // 使用 builder 模式初始化，一行代码完成所有配置！
    // Initialize with builder pattern, complete all configuration in one line!
    let manager = SaTokenConfig::builder()
        .token_name("Authorization")
        .timeout(7200)  // 2小时 | 2 hours
        .active_timeout(1800)  // 30分钟无操作超时 | 30 min idle timeout
        .is_concurrent(true)  // 允许多端登录 | Allow multi-device login
        .token_style(TokenStyle::Uuid)  // UUID 风格 | UUID style
        .storage(Arc::new(MemoryStorage::new()))
        .register_listener(Arc::new(DemoListener))  // 注册事件监听器 | Register event listener
        .build(); // 自动完成：创建 Manager + 注册监听器 + 初始化 StpUtil！
    // Auto-complete: Create Manager + Register Listeners + Initialize StpUtil!

    println!("✅ 初始化完成 | Initialization completed");
    println!("   - Token 名称 | Token Name: Authorization");
    println!("   - 超时时间 | Timeout: 7200s (2h)");
    println!("   - 活跃超时 | Active Timeout: 1800s (30min)");
    println!("   - 多端登录 | Multi-device: 是 | Yes\n");

    // ========================================
    // 步骤 2: 用户登录 | Step 2: User Login
    // ========================================
    println!("👤 步骤 2: 用户登录 | Step 2: User Login");
    println!("{}", "─".repeat(60));

    let user_id = "user_10086";

    // 方式1: 最简单的登录方式 | Method 1: Simplest login method
    let token = StpUtil::login(user_id).await?;
    println!("✅ 方式1 - 简单登录 | Method 1 - Simple Login:");
    println!("   StpUtil::login(\"{}\")", user_id);
    println!("   Token: {}\n", token.as_str());

    // 方式2: 使用 login_with_options 自定义多个字段 | Method 2: Use login_with_options with custom fields
    let user_id2 = "user_10087";
    let token2 = manager
        .login_with_options(
            user_id2,
            Some("admin".to_string()),         // login_type
            Some("iPhone 15 Pro".to_string()), // device
            Some(json!({"ip": "192.168.1.100", "location": "Beijing"})), // extra_data
            Some("nonce_abc123".to_string()),  // nonce
            None,                              // expire_time (使用配置的过期时间)
        )
        .await?;
    println!("✅ 方式2 - 自定义字段登录 | Method 2 - Login with Custom Fields:");
    println!(
        "   manager.login_with_options(login_id, login_type, device, extra_data, nonce, expire_time)"
    );
    println!("   Token: {}", token2.as_str());

    // 验证自定义字段 | Verify custom fields
    let token_info2 = StpUtil::get_token_info(&token2).await?;
    println!("   - 登录类型 | Login Type: {}", token_info2.login_type);
    println!("   - 设备信息 | Device: {:?}", token_info2.device);
    println!("   - 额外数据 | Extra Data: {:?}", token_info2.extra_data);
    println!("   - Nonce: {:?}\n", token_info2.nonce);

    // 方式3: 使用完整的 TokenInfo 对象登录 | Method 3: Login with complete TokenInfo object
    let user_id3 = "user_10088";
    let mut token_info3 = TokenInfo::new(
        TokenValue::new(""), // 空字符串，会自动生成 token
        user_id3,
    );
    token_info3.login_type = "premium".to_string();
    token_info3.device = Some("MacBook Pro".to_string());
    token_info3.extra_data = Some(json!({
        "subscription": "premium",
        "features": ["unlimited", "priority_support"]
    }));
    token_info3.nonce = Some("nonce_premium_xyz".to_string());

    let token3 = manager.login_with_token_info(token_info3).await?;
    println!("✅ 方式3 - TokenInfo 对象登录 | Method 3 - Login with TokenInfo Object:");
    println!("   let mut token_info = TokenInfo::new(...);");
    println!("   manager.login_with_token_info(token_info)");
    println!("   Token: {}", token3.as_str());

    // 验证 TokenInfo 字段 | Verify TokenInfo fields
    let token_info3_retrieved = StpUtil::get_token_info(&token3).await?;
    println!(
        "   - 登录类型 | Login Type: {}",
        token_info3_retrieved.login_type
    );
    println!("   - 设备信息 | Device: {:?}", token_info3_retrieved.device);
    println!(
        "   - 额外数据 | Extra Data: {}",
        serde_json::to_string_pretty(&token_info3_retrieved.extra_data.unwrap_or(json!(null)))?
    );
    println!();

    // ========================================
    // 步骤 3: 登录状态检查 | Step 3: Check Login Status
    // ========================================
    println!("🔍 步骤 3: 登录状态检查 | Step 3: Check Login Status");
    println!("{}", "─".repeat(60));

    // 方式1: 通过 token 检查 | Method 1: Check by token
    let is_login = StpUtil::is_login(&token).await;
    println!(
        "✅ 通过 Token 检查 | Check by Token: {}",
        if is_login {
            "✓ 已登录 | Logged In"
        } else {
            "✗ 未登录 | Not Logged In"
        }
    );

    // 方式2: 通过 login_id 检查 | Method 2: Check by login_id
    let is_login_by_id = StpUtil::is_login_by_login_id(user_id).await;
    println!(
        "✅ 通过用户ID检查 | Check by User ID: {}",
        if is_login_by_id {
            "✓ 已登录 | Logged In"
        } else {
            "✗ 未登录 | Not Logged In"
        }
    );

    // 验证登录（抛出异常）| Validate login (throws exception)
    match StpUtil::check_login(&token).await {
        Ok(_) => println!("✅ 登录验证通过 | Login validation passed"),
        Err(e) => println!("❌ 登录验证失败 | Login validation failed: {}", e),
    }
    println!();

    // ========================================
    // 步骤 4: 获取登录信息 | Step 4: Get Login Information
    // ========================================
    println!("📋 步骤 4: 获取登录信息 | Step 4: Get Login Information");
    println!("{}", "─".repeat(60));

    let login_id = StpUtil::get_login_id(&token).await?;
    println!("✅ 登录 ID | Login ID: {}", login_id);

    let token_info = StpUtil::get_token_info(&token).await?;
    println!("✅ Token 完整信息 | Token Complete Info:");
    println!("   - 登录类型 | Login Type: {}", token_info.login_type);
    println!("   - 创建时间 | Create Time: {}", token_info.create_time);
    println!(
        "   - 最后活跃 | Last Active: {}",
        token_info.last_active_time
    );
    println!("   - 设备信息 | Device: {:?}", token_info.device);
    println!();

    // ========================================
    // 步骤 5: Session 操作（现代化方式）| Step 5: Session Operations (Modern Way)
    // ========================================
    println!("💾 步骤 5: Session 操作 | Step 5: Session Operations");
    println!("{}", "─".repeat(60));

    // 设置各种类型的值 | Set various types of values
    StpUtil::set_session_value(&login_id, "username", "张三 | Zhang San").await?;
    StpUtil::set_session_value(&login_id, "age", 28).await?;
    StpUtil::set_session_value(&login_id, "is_vip", true).await?;
    StpUtil::set_session_value(&login_id, "balance", 1688.88).await?;
    println!("✅ 已设置 Session 值 | Session values set");

    // 获取值 | Get values
    let username: Option<String> = StpUtil::get_session_value(&login_id, "username").await?;
    let age: Option<i32> = StpUtil::get_session_value(&login_id, "age").await?;
    let is_vip: Option<bool> = StpUtil::get_session_value(&login_id, "is_vip").await?;
    let balance: Option<f64> = StpUtil::get_session_value(&login_id, "balance").await?;

    println!("✅ Session 数据 | Session Data:");
    println!("   - 用户名 | Username: {:?}", username);
    println!("   - 年龄 | Age: {:?}", age);
    println!("   - VIP状态 | VIP Status: {:?}", is_vip);
    println!("   - 余额 | Balance: {:?}", balance);
    println!();

    // ========================================
    // 步骤 6: Token 有效期管理 | Step 6: Token Timeout Management
    // ========================================
    println!("⏰ 步骤 6: Token 有效期管理 | Step 6: Token Timeout Management");
    println!("{}", "─".repeat(60));

    if let Some(timeout) = StpUtil::get_token_timeout(&token).await? {
        println!("✅ 当前剩余时间 | Current Remaining Time:");
        println!("   - {} 秒 | seconds", timeout);
        println!("   - {} 分钟 | minutes", timeout / 60);
        println!("   - {} 小时 | hours", timeout / 3600);
    }

    // 续期操作 | Renew operation
    StpUtil::renew_timeout(&token, 3600).await?;
    println!("✅ Token 已续期 | Token renewed: 3600s (1h)");

    if let Some(new_timeout) = StpUtil::get_token_timeout(&token).await? {
        println!(
            "   新的剩余时间 | New Remaining Time: {} 秒 | seconds",
            new_timeout
        );
    }
    println!();

    // ========================================
    // 步骤 7: 多设备登录演示 | Step 7: Multi-device Login Demo
    // ========================================
    println!("📱 步骤 7: 多设备登录 | Step 7: Multi-device Login");
    println!("{}", "─".repeat(60));

    // 同一用户在不同设备登录 | Same user logs in from different devices
    let token_mobile = StpUtil::login(user_id).await?;
    println!(
        "✅ 移动端登录 | Mobile Login: {}...",
        &token_mobile.as_str()[..20]
    );

    let token_web = StpUtil::login(user_id).await?;
    println!(
        "✅ 网页端登录 | Web Login: {}...",
        &token_web.as_str()[..20]
    );

    // 检查两个 token 都有效（因为 is_concurrent=true）
    // Check both tokens are valid (because is_concurrent=true)
    println!("\n   检查多端登录状态 | Check multi-device login status:");
    println!(
        "   - 原始 Token | Original Token: {}",
        if StpUtil::is_login(&token).await {
            "✓ 有效 | Valid"
        } else {
            "✗ 无效 | Invalid"
        }
    );
    println!(
        "   - 移动端 Token | Mobile Token: {}",
        if StpUtil::is_login(&token_mobile).await {
            "✓ 有效 | Valid"
        } else {
            "✗ 无效 | Invalid"
        }
    );
    println!(
        "   - 网页端 Token | Web Token: {}",
        if StpUtil::is_login(&token_web).await {
            "✓ 有效 | Valid"
        } else {
            "✗ 无效 | Invalid"
        }
    );
    println!();

    // ========================================
    // 步骤 8: 踢出设备 | Step 8: Kick Out Device
    // ========================================
    println!("🚫 步骤 8: 踢出设备 | Step 8: Kick Out Device");
    println!("{}", "─".repeat(60));

    // 踢出移动端 | Kick out mobile device
    StpUtil::kick_out(&token_mobile).await?;
    println!("✅ 已踢出移动端 | Mobile device kicked out");

    println!("\n   检查设备状态 | Check device status:");
    println!(
        "   - 原始 Token | Original Token: {}",
        if StpUtil::is_login(&token).await {
            "✓ 在线 | Online"
        } else {
            "✗ 离线 | Offline"
        }
    );
    println!(
        "   - 移动端 Token | Mobile Token: {}",
        if StpUtil::is_login(&token_mobile).await {
            "✓ 在线 | Online"
        } else {
            "✗ 离线 | Offline"
        }
    );
    println!(
        "   - 网页端 Token | Web Token: {}",
        if StpUtil::is_login(&token_web).await {
            "✓ 在线 | Online"
        } else {
            "✗ 离线 | Offline"
        }
    );
    println!();

    // ========================================
    // 步骤 9: 用户登出 | Step 9: User Logout
    // ========================================
    println!("👋 步骤 9: 用户登出 | Step 9: User Logout");
    println!("{}", "─".repeat(60));

    // 使用 login_id 登出所有设备 | Logout all devices by login_id
    StpUtil::logout_by_login_id(user_id).await?;
    println!(
        "✅ 用户 {} 所有设备已登出 | User {} logged out from all devices",
        user_id, user_id
    );

    println!("\n   最终状态检查 | Final status check:");
    println!(
        "   - 原始 Token | Original Token: {}",
        if StpUtil::is_login(&token).await {
            "✓ 在线 | Online"
        } else {
            "✗ 离线 | Offline"
        }
    );
    println!(
        "   - 网页端 Token | Web Token: {}",
        if StpUtil::is_login(&token_web).await {
            "✓ 在线 | Online"
        } else {
            "✗ 离线 | Offline"
        }
    );
    println!();

    // ========================================
    // 步骤 10: 新用户演示更多功能 | Step 10: New User for More Features
    // ========================================
    println!("🆕 步骤 10: 高级功能演示 | Step 10: Advanced Features Demo");
    println!("{}", "─".repeat(60));

    let new_user = "user_admin";
    let _admin_token = StpUtil::login(new_user).await?;
    println!("✅ 新用户登录 | New user logged in: {}", new_user);

    // 设置复杂的 Session 数据 | Set complex Session data
    StpUtil::set_session_value(
        new_user,
        "profile",
        serde_json::json!({
            "name": "Admin User",
            "email": "admin@example.com",
            "roles": ["admin", "editor", "viewer"]
        }),
    )
    .await?;

    println!("✅ 已设置复杂 Session 数据 | Complex Session data set");

    // 获取并显示 | Get and display
    let profile: Option<serde_json::Value> =
        StpUtil::get_session_value(new_user, "profile").await?;
    if let Some(p) = profile {
        println!(
            "   用户资料 | User Profile: {}",
            serde_json::to_string_pretty(&p)?
        );
    }
    println!();

    // ========================================
    // 步骤 11: Token 风格对比 | Step 11: Token Style Comparison
    // ========================================
    println!("🎨 步骤 11: 不同 Token 风格演示 | Step 11: Token Style Demo");
    println!("{}", "─".repeat(60));

    // 临时切换到 Random64 风格 | Temporarily switch to Random64 style
    let storage2 = Arc::new(MemoryStorage::new());
    let config2 = SaTokenConfig::builder()
        .token_style(TokenStyle::Random64)
        .build_config();
    let manager2 = SaTokenManager::new(storage2, config2);

    let random_token = manager2.login("user_temp").await?;
    println!("✅ Random64 Token 示例 | Random64 Token Example:");
    println!("   {}", random_token.as_str());
    println!(
        "   长度 | Length: {} 字符 | characters\n",
        random_token.as_str().len()
    );

    // ========================================
    // 步骤 12: 批量操作 | Step 12: Batch Operations
    // ========================================
    println!("🔄 步骤 12: 批量操作演示 | Step 12: Batch Operations Demo");
    println!("{}", "─".repeat(60));

    // 批量登录多个用户 | Batch login multiple users
    let users = vec!["user_001", "user_002", "user_003"];
    println!(
        "📝 批量登录 {} 个用户 | Batch login {} users",
        users.len(),
        users.len()
    );

    for user in &users {
        let t = StpUtil::login(user).await?;
        println!(
            "   ✓ {} 登录成功 | logged in: {}...",
            user,
            &t.as_str()[..16]
        );
    }

    // 检查在线状态 | Check online status
    println!("\n   在线用户检查 | Online users check:");
    for user in &users {
        let online = StpUtil::is_login_by_login_id(user).await;
        println!(
            "   - {}: {}",
            user,
            if online {
                "🟢 在线 | Online"
            } else {
                "🔴 离线 | Offline"
            }
        );
    }

    // 批量登出 | Batch logout
    println!("\n📝 批量登出 | Batch logout");
    for user in &users {
        StpUtil::logout_by_login_id(user).await?;
        println!("   ✓ {} 已登出 | logged out", user);
    }
    println!();

    // ========================================
    // 步骤 13: 错误处理演示 | Step 13: Error Handling Demo
    // ========================================
    println!("⚠️  步骤 13: 错误处理演示 | Step 13: Error Handling Demo");
    println!("{}", "─".repeat(60));

    let invalid_token = "invalid-token-12345".to_string().into();

    match StpUtil::check_login(&invalid_token).await {
        Ok(_) => println!("   验证通过 | Validation passed"),
        Err(e) => println!("✅ 正确捕获错误 | Correctly caught error: {}", e),
    }

    match StpUtil::get_login_id(&invalid_token).await {
        Ok(id) => println!("   获取到 ID | Got ID: {}", id),
        Err(e) => println!("✅ 正确捕获错误 | Correctly caught error: {}", e),
    }
    println!();

    // ========================================
    // 步骤 14: 总结 | Step 14: Summary
    // ========================================
    println!("📊 步骤 14: 功能总结 | Step 14: Feature Summary");
    println!("{}", "─".repeat(60));
    println!("\n本示例展示了以下功能 | This example demonstrates:");
    println!("  ✓ 用户登录/登出 | User Login/Logout");
    println!("  ✓ 多设备登录管理 | Multi-device Login Management");
    println!("  ✓ Token 状态检查 | Token Status Check");
    println!("  ✓ Session 数据操作 | Session Data Operations");
    println!("  ✓ Token 有效期管理 | Token Timeout Management");
    println!("  ✓ 设备踢出功能 | Device Kick-out");
    println!("  ✓ 事件监听集成 | Event Listener Integration");
    println!("  ✓ 批量操作 | Batch Operations");
    println!("  ✓ 错误处理 | Error Handling");
    println!("  ✓ 不同 Token 风格 | Different Token Styles");

    println!("\n{}", "═".repeat(60));
    println!("✅ 所有示例执行完成！| All examples completed!");
    println!("{}", "═".repeat(60));

    println!("\n💡 提示 | Tips:");
    println!("   在实际项目中，推荐使用 Web 框架插件：");
    println!("   In real projects, recommend using Web framework plugins:");
    println!("   ");
    println!("   cargo add sa-token-plugin-axum");
    println!("   use sa_token_plugin_axum::*;");
    println!();

    Ok(())
}
