// Author: 金书记
//
//! 事件监听示例
//!
//! 演示如何使用 sa-token 的事件监听功能
//!
//! ## 导入方式
//!
//! ### 方式1: 独立使用核心库（本示例）
//! ```ignore
//! use sa_token_core::{SaTokenManager, SaTokenConfig, ...};
//! use sa_token_storage_memory::MemoryStorage;
//! ```
//!
//! ### 方式2: 使用 Web 框架插件（推荐）
//! 如果你在 Web 项目中使用，只需一行导入：
//! ```ignore
//! use sa_token_plugin_axum::*;  // 或 actix-web, poem, rocket, warp
//! // 所有功能已重新导出！
//! ```

#![allow(clippy::print_stdout, clippy::print_stderr)]

use async_trait::async_trait;
use sa_token_core::{LoggingListener, SaTokenConfig, SaTokenListener, StpUtil, WsAuthManager};
use sa_token_storage_memory::MemoryStorage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 自定义监听器 - 记录用户行为 | Custom Listener - Track User Behavior
struct UserBehaviorListener {
    websocket_sessions: Arc<RwLock<HashMap<String, usize>>>,
}

impl UserBehaviorListener {
    fn new() -> Self {
        Self {
            websocket_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl SaTokenListener for UserBehaviorListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        if login_type == "websocket" {
            // WebSocket 认证 | WebSocket Authentication
            let mut sessions = self.websocket_sessions.write().await;
            let count = sessions.entry(login_id.to_string()).or_insert(0);
            *count += 1;

            println!("📝 [用户行为记录 | User Behavior Log] WebSocket 连接 | WebSocket Connection");
            println!("   - 用户ID | User ID: {}", login_id);
            println!("   - Token: {}...", &token[..20.min(token.len())]);
            println!("   - 登录类型 | Login Type: 🌐 {}", login_type);
            println!(
                "   - 该用户的 WebSocket 连接数 | WebSocket Connections: {}",
                *count
            );
        } else {
            // 普通登录 | Regular Login
            println!("📝 [用户行为记录 | User Behavior Log] 用户登录 | User Login");
            println!("   - 用户ID | User ID: {}", login_id);
            println!("   - Token: {}...", &token[..20.min(token.len())]);
            println!("   - 登录类型 | Login Type: {}", login_type);
        }

        // 这里可以添加实际的业务逻辑，例如：
        // Here you can add actual business logic, such as:
        // - 记录登录日志到数据库 | Log to database
        // - 更新用户最后登录时间 | Update last login time
        // - 发送登录通知 | Send login notification
        // - 统计登录次数 | Count login times
    }

    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        println!("📝 [用户行为记录 | User Behavior Log] 用户登出 | User Logout");
        println!("   - 用户ID | User ID: {}", login_id);
        println!("   - Token: {}", token);
        println!("   - 登录类型 | Login Type: {}", login_type);

        // 业务逻辑 | Business Logic:
        // - 记录登出日志 | Log logout event
        // - 清理用户缓存 | Clear user cache
        // - 更新在线状态 | Update online status
    }

    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {
        println!("⚠️  [用户行为记录 | User Behavior Log] 用户被踢出下线 | User Kicked Out");
        println!("   - 用户ID | User ID: {}", login_id);
        println!("   - Token: {}", token);
        println!("   - 登录类型 | Login Type: {}", login_type);

        // 业务逻辑 | Business Logic:
        // - 记录踢出日志 | Log kick-out event
        // - 发送通知给用户 | Send notification to user
        // - 清理会话数据 | Clean session data
    }
}

/// 安全监控监听器 - 监控可疑行为 | Security Monitor Listener - Monitor Suspicious Behavior
struct SecurityMonitorListener;

#[async_trait]
impl SaTokenListener for SecurityMonitorListener {
    async fn on_login(&self, login_id: &str, _token: &str, _login_type: &str) {
        // 检查是否存在异常登录 | Check for abnormal login
        println!("🔒 [安全监控 | Security Monitor] 检查登录安全性 | Check Login Security");
        println!("   - 用户ID | User ID: {}", login_id);

        // 实际业务逻辑 | Actual Business Logic:
        // - 检查登录IP是否在白名单 | Check if IP is whitelisted
        // - 检查登录频率是否异常
        // - 检查是否需要二次验证
    }

    async fn on_kick_out(&self, login_id: &str, _token: &str, _login_type: &str) {
        println!("🚨 [安全监控] 用户被强制下线");
        println!("   - 用户ID: {}", login_id);

        // 实际业务逻辑：
        // - 记录安全事件
        // - 发送告警通知
        // - 触发安全审计
    }
}

/// 统计监听器 - 统计用户活跃度
struct StatisticsListener {
    login_count: Arc<RwLock<u64>>,
    logout_count: Arc<RwLock<u64>>,
}

impl StatisticsListener {
    fn new() -> Self {
        Self {
            login_count: Arc::new(RwLock::new(0)),
            logout_count: Arc::new(RwLock::new(0)),
        }
    }

    async fn get_stats(&self) -> (u64, u64) {
        let login_count = *self.login_count.read().await;
        let logout_count = *self.logout_count.read().await;
        (login_count, logout_count)
    }
}

#[async_trait]
impl SaTokenListener for StatisticsListener {
    async fn on_login(&self, _login_id: &str, _token: &str, _login_type: &str) {
        let mut count = self.login_count.write().await;
        *count += 1;
        println!("📊 [统计] 登录次数: {}", *count);
    }

    async fn on_logout(&self, _login_id: &str, _token: &str, _login_type: &str) {
        let mut count = self.logout_count.write().await;
        *count += 1;
        println!("📊 [统计] 登出次数: {}", *count);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== sa-token 事件监听示例 ===\n");

    // 创建监听器实例（需要在后续访问的监听器）
    // Create listener instances (for listeners that need to be accessed later)
    let behavior_listener = Arc::new(UserBehaviorListener::new());
    let stats_listener = Arc::new(StatisticsListener::new());

    println!(">>> 使用 Builder 模式注册事件监听器...\n");

    // 使用 Builder 模式一次性完成所有配置！
    // Use Builder pattern to complete all configuration at once!
    let manager = SaTokenConfig::builder()
        .timeout(7200)  // 2小时过期 | 2 hours expiration
        .storage(Arc::new(MemoryStorage::new()))
        .register_listener(Arc::new(LoggingListener))  // 日志监听器 | Logging listener
        .register_listener(behavior_listener.clone() as Arc<dyn SaTokenListener>)  // 行为监听器 | Behavior listener
        .register_listener(Arc::new(SecurityMonitorListener))  // 安全监听器 | Security listener
        .register_listener(stats_listener.clone() as Arc<dyn SaTokenListener>)  // 统计监听器 | Statistics listener
        .build(); // 自动完成：创建 Manager + 注册监听器 + 初始化 StpUtil！

    // 注：虽然 build() 已经自动初始化了 StpUtil，但我们保留 manager 变量用于后续的 WebSocket 测试
    // Note: Although build() has automatically initialized StpUtil, we keep the manager variable for later WebSocket tests

    println!("✅ 已注册 4 个监听器（自动初始化完成！）\n");

    // 注：也可以在 build() 后手动注册更多监听器
    // Note: You can also manually register more listeners after build()
    // StpUtil::event_bus().register(Arc::new(AnotherListener));

    // 5. 测试登录事件
    println!("\n========================================");
    println!(">>> 测试1: 用户登录");
    println!("========================================\n");

    let token1 = StpUtil::login("user_10086").await?;
    println!("\n生成的 Token: {}\n", token1.as_str());

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // 6. 测试第二个用户登录
    println!("\n========================================");
    println!(">>> 测试2: 另一个用户登录");
    println!("========================================\n");

    let token2 = StpUtil::login("user_10087").await?;
    println!("\n生成的 Token: {}\n", token2.as_str());

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // 7. 测试登出事件
    println!("\n========================================");
    println!(">>> 测试3: 用户登出");
    println!("========================================\n");

    StpUtil::logout(&token1).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // 8. 测试踢出下线事件
    println!("\n========================================");
    println!(">>> 测试4: 踢出用户下线");
    println!("========================================\n");

    StpUtil::kick_out("user_10087").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // 9. 测试 WebSocket 认证事件
    println!("\n========================================");
    println!(">>> 测试5: WebSocket 认证（触发 Login 事件）");
    println!("========================================\n");

    let manager_arc = Arc::new(manager.clone());
    let ws_auth = WsAuthManager::new(manager_arc);

    // 先登录获取 token
    let ws_token = StpUtil::login("ws_user_001").await?;
    println!("用户 ws_user_001 已登录\n");

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // WebSocket 认证（使用 Authorization Header）
    println!("WebSocket 认证 - 方式1: Authorization Header");
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        format!("Bearer {}", ws_token.as_str()),
    );

    let ws_auth_info = ws_auth.authenticate(&headers, &HashMap::new()).await?;
    println!("WebSocket 会话 ID: {}\n", ws_auth_info.session_id);

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // 10. 测试多设备 WebSocket 连接
    println!("\n========================================");
    println!(">>> 测试6: 多设备 WebSocket 连接");
    println!("========================================\n");

    println!("同一用户从多个设备连接...\n");

    // 设备2: 使用 Query 参数
    println!("WebSocket 认证 - 方式2: Query Parameter");
    let mut query = HashMap::new();
    query.insert("token".to_string(), ws_token.as_str().to_string());

    let ws_auth_info2 = ws_auth.authenticate(&HashMap::new(), &query).await?;
    println!("WebSocket 会话 ID: {}\n", ws_auth_info2.session_id);

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // 设备3: 使用 WebSocket Protocol Header
    println!("WebSocket 认证 - 方式3: Sec-WebSocket-Protocol Header");
    let mut headers2 = HashMap::new();
    headers2.insert(
        "Sec-WebSocket-Protocol".to_string(),
        ws_token.as_str().to_string(),
    );

    let ws_auth_info3 = ws_auth.authenticate(&headers2, &HashMap::new()).await?;
    println!("WebSocket 会话 ID: {}\n", ws_auth_info3.session_id);

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // 11. 显示 WebSocket 连接统计
    println!("\n========================================");
    println!(">>> WebSocket 连接统计");
    println!("========================================\n");

    let ws_sessions = behavior_listener.websocket_sessions.read().await;
    if let Some(count) = ws_sessions.get("ws_user_001") {
        println!("用户 ws_user_001 的 WebSocket 连接数: {}", count);
    }
    println!();

    // 12. 显示总体统计信息
    println!("\n========================================");
    println!(">>> 总体统计信息");
    println!("========================================\n");

    let (login_count, logout_count) = stats_listener.get_stats().await;
    println!(
        "总登录次数: {} (包括普通登录 + WebSocket 认证)",
        login_count
    );
    println!("总登出次数: {}", logout_count);

    println!("\n💡 事件监听说明:");
    println!("   • 普通登录: login_type = 'default'");
    println!("   • WebSocket 认证: login_type = 'websocket'");
    println!("   • 监听器可以通过 login_type 区分不同类型的登录");
    println!("   • WebSocket 认证会触发 Login 事件，与普通登录使用相同的事件系统");

    println!("\n✅ 事件监听示例运行完成！");

    Ok(())
}
