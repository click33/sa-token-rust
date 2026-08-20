// Author: 金书记
//
//! JWT (JSON Web Token) 使用示例
//!
//! 演示 sa-token 的完整 JWT 功能
//!
//! ## 导入方式
//!
//! ### 方式1: 独立使用核心库（本示例）
//! ```ignore
//! use sa_token_core::{JwtManager, JwtClaims, JwtAlgorithm, ...};
//! ```
//!
//! ### 方式2: 使用 Web 框架插件（推荐）
//! 如果你在 Web 项目中使用，只需一行导入：
//! ```toml
//! [dependencies]
//! sa-token-plugin-axum = "0.1.3"  // 默认包含所有功能
//! ```
//! ```ignore
//! use sa_token_plugin_axum::*;  // JWT 相关类型已重新导出！
//! ```

#![allow(clippy::print_stdout, clippy::print_stderr)]

use sa_token_core::{
    JwtAlgorithm, JwtClaims, JwtManager, SaTokenConfig, SaTokenManager, StpUtil, config::TokenStyle,
};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("========================================");
    println!("sa-token JWT 功能示例 | sa-token JWT Features Example");
    println!("========================================\n");

    // ========================================
    // 示例 1: 使用独立的 JWT Manager | Example 1: Use JWT Manager Independently
    // ========================================
    println!(">>> 示例 1: 独立使用 JWT Manager | Example 1: Use JWT Manager Independently\n");

    // 创建 JWT 管理器
    let jwt_manager = JwtManager::new("my-secret-key-123456")
        .set_issuer("sa-token-rust")
        .set_audience("web-app");

    // 创建 JWT Claims
    let mut claims = JwtClaims::new("user_10086");
    claims.set_expiration(3600); // 1小时过期
    claims.set_login_type("user");
    claims.set_device("web-browser");
    claims.add_claim("role", serde_json::json!("admin"));
    claims.add_claim(
        "permissions",
        serde_json::json!(["read", "write", "delete"]),
    );

    println!("创建的 Claims:");
    println!("  - 用户ID: {}", claims.login_id);
    println!("  - 登录类型: {:?}", claims.login_type);
    println!("  - 设备: {:?}", claims.device);
    println!("  - 角色: {:?}", claims.get_claim("role"));
    println!("  - 权限: {:?}\n", claims.get_claim("permissions"));

    // 生成 JWT Token
    let jwt_token = jwt_manager.generate(&claims)?;
    println!("生成的 JWT Token:");
    println!("{}\n", jwt_token);

    // 验证并解析 JWT Token
    let decoded_claims = jwt_manager.validate(&jwt_token)?;
    println!("解码的 Claims:");
    println!("  - 用户ID: {}", decoded_claims.login_id);
    println!(
        "  - 剩余有效时间: {:?} 秒\n",
        decoded_claims.remaining_time()
    );

    // ========================================
    // 示例 2: 在 sa-token Manager 中使用 JWT
    // ========================================
    println!("\n========================================");
    println!(">>> 示例 2: 在 sa-token 中使用 JWT Token Style\n");

    // 创建使用 JWT Token Style 的配置 | Create config with JWT Token Style
    let storage = Arc::new(MemoryStorage::new());
    let config = SaTokenConfig::builder()
        .timeout(7200) // 2小时 | 2 hours
        .token_style(TokenStyle::Jwt)
        .jwt_secret_key("my-super-secret-key-123456")
        .jwt_algorithm("HS256")
        .jwt_issuer("sa-token-rust")
        .jwt_audience("mobile-app")
        .build_config();

    let manager = SaTokenManager::new(storage, config);
    StpUtil::try_init_manager(manager.clone())?;

    println!("配置信息 | Configuration:");
    println!("  - Token Style: JWT");
    println!("  - 算法 | Algorithm: HS256");
    println!("  - 签发者 | Issuer: sa-token-rust");
    println!("  - 受众 | Audience: mobile-app\n");

    // 登录生成 JWT Token | Login to generate JWT Token
    let token = StpUtil::login("user_10087").await?;
    println!("登录成功，生成的 JWT Token | Login successful, generated JWT Token:");
    println!("{}\n", token.as_str());

    // 验证 Token | Validate Token
    let is_valid = StpUtil::is_login(&token).await;
    println!(
        "Token 验证结果 | Token Validation Result: {}\n",
        if is_valid {
            "✓ 有效 | Valid"
        } else {
            "✗ 无效 | Invalid"
        }
    );

    // ========================================
    // 示例 3: JWT Token 刷新 | Example 3: JWT Token Refresh
    // ========================================
    println!("\n========================================");
    println!(">>> 示例 3: JWT Token 刷新 | Example 3: JWT Token Refresh\n");

    let jwt_manager = JwtManager::new("refresh-secret-key");

    // 创建短期 Token
    let mut short_claims = JwtClaims::new("user_10088");
    short_claims.set_expiration(60); // 1分钟
    let short_token = jwt_manager.generate(&short_claims)?;

    println!(
        "原始 Token 剩余时间: {} 秒",
        jwt_manager
            .validate(&short_token)?
            .remaining_time()
            .unwrap()
    );

    // 刷新 Token（延长2小时）
    let refreshed_token = jwt_manager.refresh(&short_token, 7200)?;

    println!(
        "刷新后 Token 剩余时间: {} 秒\n",
        jwt_manager
            .validate(&refreshed_token)?
            .remaining_time()
            .unwrap()
    );

    // ========================================
    // 示例 4: 不同算法的 JWT
    // ========================================
    println!("\n========================================");
    println!(">>> 示例 4: 支持多种算法\n");

    let algorithms = vec![
        (JwtAlgorithm::HS256, "HS256"),
        (JwtAlgorithm::HS384, "HS384"),
        (JwtAlgorithm::HS512, "HS512"),
    ];

    for (alg, name) in algorithms {
        let manager = JwtManager::with_algorithm("test-secret", alg);
        let mut claims = JwtClaims::new("user_test");
        claims.set_expiration(3600);

        match manager.generate(&claims) {
            Ok(token) => {
                println!("✓ {} 算法生成成功，Token 长度: {} 字符", name, token.len());
                // 验证
                if manager.validate(&token).is_ok() {
                    println!("  ✓ 验证通过");
                }
            }
            Err(e) => println!("✗ {} 算法失败: {:?}", name, e),
        }
    }

    // ========================================
    // 示例 5: 自定义 Claims
    // ========================================
    println!("\n========================================");
    println!(">>> 示例 5: 使用自定义 Claims\n");

    let jwt_manager = JwtManager::new("custom-claims-secret");

    let mut claims = JwtClaims::new("user_10089");
    claims.set_expiration(3600);

    // 添加各种自定义数据
    claims.add_claim("username", serde_json::json!("张三"));
    claims.add_claim("email", serde_json::json!("zhangsan@example.com"));
    claims.add_claim("age", serde_json::json!(28));
    claims.add_claim("is_premium", serde_json::json!(true));
    claims.add_claim(
        "metadata",
        serde_json::json!({
            "last_login": "2025-01-01 10:00:00",
            "login_count": 42,
            "preferences": {
                "theme": "dark",
                "language": "zh-CN"
            }
        }),
    );

    let token = jwt_manager.generate(&claims)?;
    let decoded = jwt_manager.validate(&token)?;

    println!("自定义 Claims 内容:");
    println!("  - 用户名: {:?}", decoded.get_claim("username"));
    println!("  - 邮箱: {:?}", decoded.get_claim("email"));
    println!("  - 年龄: {:?}", decoded.get_claim("age"));
    println!("  - 是否高级用户: {:?}", decoded.get_claim("is_premium"));
    println!("  - 元数据: {:?}\n", decoded.get_claim("metadata"));

    // ========================================
    // 示例 6: 快速提取用户ID
    // ========================================
    println!("\n========================================");
    println!(">>> 示例 6: 快速提取用户ID（不完全验证）\n");

    let jwt_manager = JwtManager::new("extract-secret");
    let mut claims = JwtClaims::new("quick_user_123");
    claims.set_expiration(3600);
    let token = jwt_manager.generate(&claims)?;

    // 快速提取（不验证签名，适合需要快速识别用户的场景）
    let user_id = jwt_manager.extract_login_id(&token)?;
    println!("快速提取的用户ID: {}", user_id);
    println!("（注意：此方法不验证签名，仅用于快速识别）\n");

    // ========================================
    // 总结
    // ========================================
    println!("\n========================================");
    println!("✅ JWT 功能演示完成！");
    println!("========================================\n");

    println!("JWT 功能特性：");
    println!("  ✓ 多种算法支持（HS256, HS384, HS512, RS256等）");
    println!("  ✓ 自定义 Claims");
    println!("  ✓ Token 刷新");
    println!("  ✓ 过期时间验证");
    println!("  ✓ 签发者和受众验证");
    println!("  ✓ 与 sa-token 无缝集成");
    println!("  ✓ 快速用户识别");

    Ok(())
}
