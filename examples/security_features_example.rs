// Author: 金书记
//
//! 安全功能示例：防重放攻击和 Token 刷新
//!
//! 演示如何使用 Nonce 防止重放攻击和 Refresh Token 机制
//!
//! ## 导入方式
//!
//! ### 方式1: 独立使用核心库（本示例）
//! ```ignore
//! use sa_token_core::{NonceManager, RefreshTokenManager, ...};
//! ```
//!
//! ### 方式2: 使用 Web 框架插件（推荐）
//! ```toml
//! [dependencies]
//! sa-token-plugin-axum = "0.1.3"
//! ```
//! ```ignore
//! use sa_token_plugin_axum::*;  // 安全功能已重新导出！
//! ```

#![allow(clippy::print_stdout, clippy::print_stderr)]

use sa_token_core::{
    LOGIN_TYPE_DEFAULT, NonceManager, RefreshTokenManager, SaTokenConfig, config::TokenStyle,
};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("========================================");
    println!("sa-token 安全功能示例 | sa-token Security Features Example");
    println!("========================================\n");

    let storage = Arc::new(MemoryStorage::new());

    // ========================================
    // 示例 1: Nonce 防重放攻击 | Example 1: Nonce for Replay Attack Prevention
    // ========================================
    println!(
        ">>> 示例 1: 使用 Nonce 防止重放攻击 | Example 1: Use Nonce to Prevent Replay Attacks\n"
    );

    let nonce_manager = NonceManager::new(storage.clone(), 60);

    // 生成 nonce
    let nonce1 = nonce_manager.generate();
    let nonce2 = nonce_manager.generate();

    println!("生成的 Nonce:");
    println!("  Nonce 1: {}", nonce1);
    println!("  Nonce 2: {}\n", nonce2);

    // 验证 nonce（首次使用）
    println!("首次验证 Nonce 1:");
    match nonce_manager
        .validate_and_consume(&nonce1, "user_123")
        .await
    {
        Ok(_) => println!("  ✓ 验证成功，nonce 已被标记为使用\n"),
        Err(e) => println!("  ✗ 验证失败: {:?}\n", e),
    }

    // 尝试重复使用（模拟重放攻击）
    println!("再次验证相同的 Nonce 1（模拟重放攻击）:");
    match nonce_manager
        .validate_and_consume(&nonce1, "user_123")
        .await
    {
        Ok(_) => println!("  ✗ 验证成功（不应该发生！）\n"),
        Err(e) => println!("  ✓ 检测到重放攻击，拒绝请求: {:?}\n", e),
    }

    // 检查时间戳
    println!("检查 Nonce 时间戳:");
    match nonce_manager.check_timestamp(&nonce2, 60) {
        Ok(valid) => {
            if valid {
                println!("  ✓ Nonce 在有效时间窗口内（60秒）\n");
            } else {
                println!("  ✗ Nonce 超出有效时间窗口\n");
            }
        }
        Err(e) => println!("  ✗ 时间戳检查失败: {:?}\n", e),
    }

    // ========================================
    // 示例 2: Refresh Token 机制
    // ========================================
    println!("\n========================================");
    println!(">>> 示例 2: Refresh Token 刷新机制\n");

    let config = Arc::new(SaTokenConfig {
        token_style: TokenStyle::Uuid,
        timeout: 3600,                 // 访问令牌 1 小时
        refresh_token_timeout: 604800, // refresh token 7 天
        enable_refresh_token: true,
        ..Default::default()
    });

    let refresh_manager = RefreshTokenManager::from_storage(storage.clone(), config.clone());

    // 生成 refresh token
    let refresh_token = refresh_manager.generate("user_10086");
    let access_token = "access_token_abc123";

    println!("生成 Token 对:");
    println!("  Access Token:  {}", access_token);
    println!("  Refresh Token: {}\n", refresh_token);

    // 存储 refresh token
    refresh_manager
        .store(
            &refresh_token,
            access_token,
            LOGIN_TYPE_DEFAULT,
            "user_10086",
        )
        .await?;
    println!("✓ Refresh Token 已存储\n");

    // 验证 refresh token
    println!("验证 Refresh Token:");
    match refresh_manager.validate(&refresh_token).await {
        Ok(login_id) => println!("  ✓ 验证成功，用户ID: {}\n", login_id),
        Err(e) => println!("  ✗ 验证失败: {:?}\n", e),
    }

    // 使用 refresh token 刷新访问令牌
    println!("使用 Refresh Token 刷新访问令牌:");
    match refresh_manager.refresh_access_token(&refresh_token).await {
        Ok((new_access_token, login_id)) => {
            println!("  ✓ 刷新成功！");
            println!("  用户ID: {}", login_id);
            println!("  新的 Access Token: {}", new_access_token.as_str());
            println!("  原 Access Token: {}\n", access_token);
        }
        Err(e) => println!("  ✗ 刷新失败: {:?}\n", e),
    }

    // 删除 refresh token（登出）
    println!("删除 Refresh Token:");
    refresh_manager.delete(&refresh_token).await?;
    println!("  ✓ Refresh Token 已删除\n");

    // 尝试使用已删除的 refresh token
    println!("尝试使用已删除的 Refresh Token:");
    match refresh_manager.validate(&refresh_token).await {
        Ok(_) => println!("  ✗ 验证成功（不应该发生！）\n"),
        Err(e) => println!("  ✓ 验证失败（预期结果）: {:?}\n", e),
    }

    // ========================================
    // 示例 3: 完整的安全认证流程
    // ========================================
    println!("\n========================================");
    println!(">>> 示例 3: 完整的安全认证流程\n");

    let config_full = Arc::new(SaTokenConfig {
        token_style: TokenStyle::Tik,
        timeout: 1800,                  // 访问令牌 30 分钟
        refresh_token_timeout: 2592000, // refresh token 30 天
        enable_refresh_token: true,
        enable_nonce: true,
        nonce_timeout: 300, // nonce 5 分钟
        ..Default::default()
    });

    println!("安全配置:");
    println!("  Access Token 有效期: 30 分钟");
    println!("  Refresh Token 有效期: 30 天");
    println!("  Nonce 有效期: 5 分钟");
    println!("  Token 风格: Tik (短小精悍)\n");

    let nonce_mgr = NonceManager::new(storage.clone(), config_full.nonce_timeout);
    let refresh_mgr = RefreshTokenManager::from_storage(storage.clone(), config_full.clone());

    // 步骤1: 用户登录
    println!("步骤1: 用户登录");
    let login_nonce = nonce_mgr.generate();
    println!("  生成登录 nonce: {}", login_nonce);
    nonce_mgr
        .validate_and_consume(&login_nonce, "user_10087")
        .await?;

    let user_access_token = "tik_abc123";
    let user_refresh_token = refresh_mgr.generate("user_10087");
    refresh_mgr
        .store(
            &user_refresh_token,
            user_access_token,
            LOGIN_TYPE_DEFAULT,
            "user_10087",
        )
        .await?;

    println!("  ✓ 登录成功");
    println!("  Access Token: {}", user_access_token);
    println!("  Refresh Token: {}\n", user_refresh_token);

    // 步骤2: API 请求（带 nonce）
    println!("步骤2: API 请求（使用 nonce 防重放）");
    let api_nonce = nonce_mgr.generate();
    println!("  请求 nonce: {}", api_nonce);
    nonce_mgr
        .validate_and_consume(&api_nonce, "user_10087")
        .await?;
    println!("  ✓ 请求成功\n");

    // 步骤3: 尝试重放攻击
    println!("步骤3: 检测重放攻击");
    match nonce_mgr
        .validate_and_consume(&api_nonce, "user_10087")
        .await
    {
        Ok(_) => println!("  ✗ 重放攻击成功（不应该发生！）\n"),
        Err(_) => println!("  ✓ 重放攻击被阻止\n"),
    }

    // 步骤4: Access Token 过期，使用 Refresh Token 刷新
    println!("步骤4: Access Token 过期，使用 Refresh Token 刷新");
    let (new_token, _) = refresh_mgr
        .refresh_access_token(&user_refresh_token)
        .await?;
    println!("  ✓ Token 刷新成功");
    println!("  新 Access Token: {}\n", new_token.as_str());

    // 步骤5: 用户登出
    println!("步骤5: 用户登出");
    refresh_mgr.delete(&user_refresh_token).await?;
    println!("  ✓ Refresh Token 已撤销\n");

    // ========================================
    // 安全特性总结
    // ========================================
    println!("\n========================================");
    println!("✅ 安全功能演示完成！");
    println!("========================================\n");

    println!("安全特性说明:\n");

    println!("【防重放攻击 - Nonce 机制】");
    println!("  ✓ 每个请求使用唯一的 nonce");
    println!("  ✓ nonce 只能使用一次");
    println!("  ✓ 带时间戳验证，防止过期 nonce");
    println!("  ✓ 有效阻止重放攻击\n");

    println!("【Token 刷新机制 - Refresh Token】");
    println!("  ✓ 短期 Access Token（高安全性）");
    println!("  ✓ 长期 Refresh Token（好体验）");
    println!("  ✓ 无需频繁输入密码");
    println!("  ✓ 可随时撤销 Refresh Token\n");

    println!("【最佳实践】");
    println!("  • Access Token 有效期: 15-60 分钟");
    println!("  • Refresh Token 有效期: 7-30 天");
    println!("  • Nonce 有效期: 5-10 分钟");
    println!("  • HTTPS 传输，避免中间人攻击");
    println!("  • 存储 Refresh Token 在安全位置");
    println!("  • 登出时删除所有 Token");

    Ok(())
}
