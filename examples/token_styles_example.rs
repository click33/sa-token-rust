// Author: 金书记
//
//! Token 风格示例
//!
//! 演示所有可用的 Token 生成风格
//!
//! ## 导入方式
//!
//! ### 方式1: 独立使用核心库（本示例）
//! ```ignore
//! use sa_token_core::config::{SaTokenConfig, TokenStyle};
//! use sa_token_core::token::TokenGenerator;
//! ```
//!
//! ### 方式2: 使用 Web 框架插件（推荐）
//! ```toml
//! [dependencies]
//! sa-token-plugin-axum = "0.1.3"
//! ```
//! ```ignore
//! use sa_token_plugin_axum::*;  // TokenStyle 已重新导出！
//! ```

#![allow(clippy::print_stdout, clippy::print_stderr)]

use sa_token_core::{
    config::{SaTokenConfig, TokenStyle},
    token::TokenGenerator,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("========================================");
    println!("sa-token Token 风格示例 | sa-token Token Styles Example");
    println!("========================================\n");

    let test_login_id = "user_12345";

    // ========================================
    // 1. UUID 风格 | 1. UUID Style
    // ========================================
    println!("1. UUID 风格 | UUID Style:");
    let token = TokenGenerator::generate_with_login_id(
        &SaTokenConfig {
            token_style: TokenStyle::Uuid,
            ..Default::default()
        },
        test_login_id,
    )?;
    println!("   Token: {}", token.as_str());
    println!(
        "   长度 | Length: {} 字符 | characters\n",
        token.as_str().len()
    );

    // ========================================
    // 2. Simple UUID 风格 | 2. Simple UUID Style
    // ========================================
    println!("2. Simple UUID 风格（无横杠）| Simple UUID Style (no hyphens):");
    let token = TokenGenerator::generate_with_login_id(
        &SaTokenConfig {
            token_style: TokenStyle::SimpleUuid,
            ..Default::default()
        },
        test_login_id,
    )?;
    println!("   Token: {}", token.as_str());
    println!(
        "   长度 | Length: {} 字符 | characters\n",
        token.as_str().len()
    );

    // 3. Random32 风格
    println!("3. Random32 风格:");
    let token = TokenGenerator::generate_with_login_id(
        &SaTokenConfig {
            token_style: TokenStyle::Random32,
            ..Default::default()
        },
        test_login_id,
    )?;
    println!("   Token: {}", token.as_str());
    println!("   长度: {} 字符\n", token.as_str().len());

    // 4. Random64 风格
    println!("4. Random64 风格:");
    let token = TokenGenerator::generate_with_login_id(
        &SaTokenConfig {
            token_style: TokenStyle::Random64,
            ..Default::default()
        },
        test_login_id,
    )?;
    println!("   Token: {}", token.as_str());
    println!("   长度: {} 字符\n", token.as_str().len());

    // 5. Hash 风格（新）
    println!("5. Hash 风格 (NEW - SHA256哈希):");
    let config_hash = SaTokenConfig {
        token_style: TokenStyle::Hash,
        ..Default::default()
    };
    let token = TokenGenerator::generate_with_login_id(&config_hash, test_login_id)?;
    println!("   Token: {}", token.as_str());
    println!("   长度: {} 字符", token.as_str().len());
    println!("   说明: SHA256(login_id + timestamp + UUID)\n");

    // 6. Timestamp 风格（新）
    println!("6. Timestamp 风格 (NEW - 时间戳+随机):");
    let config_timestamp = SaTokenConfig {
        token_style: TokenStyle::Timestamp,
        ..Default::default()
    };
    let token = TokenGenerator::generate_with_login_id(&config_timestamp, test_login_id)?;
    println!("   Token: {}", token.as_str());
    println!("   长度: {} 字符", token.as_str().len());
    println!("   说明: 毫秒级时间戳_16位随机字符\n");

    // 7. Tik 风格（新）
    println!("7. Tik 风格 (NEW - 短小精悍):");
    let config_tik = SaTokenConfig {
        token_style: TokenStyle::Tik,
        ..Default::default()
    };
    let token = TokenGenerator::generate_with_login_id(&config_tik, test_login_id)?;
    println!("   Token: {}", token.as_str());
    println!("   长度: {} 字符", token.as_str().len());
    println!("   说明: 8位字母数字混合（URL安全）\n");

    // 生成多个 Token 验证唯一性
    println!("\n========================================");
    println!("验证新 Token 风格的唯一性");
    println!("========================================\n");

    println!("Hash 风格 (3次生成):");
    for i in 1..=3 {
        let token = TokenGenerator::generate_with_login_id(&config_hash, test_login_id)?;
        println!("  #{}: {}", i, token.as_str());
    }

    println!("\nTimestamp 风格 (3次生成):");
    for i in 1..=3 {
        let token = TokenGenerator::generate_with_login_id(&config_timestamp, test_login_id)?;
        println!("  #{}: {}", i, token.as_str());
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    println!("\nTik 风格 (5次生成 - 展示短小特性):");
    for i in 1..=5 {
        let token = TokenGenerator::generate_with_login_id(&config_tik, test_login_id)?;
        println!("  #{}: {}", i, token.as_str());
    }

    println!("\n========================================");
    println!("Token 风格对比");
    println!("========================================\n");

    println!("风格       | 长度    | 特点");
    println!("-----------|---------|------------------------------------------");
    println!("UUID       | 36 字符 | 标准 UUID 格式，带横杠");
    println!("SimpleUUID | 32 字符 | UUID 格式，无横杠");
    println!("Random32   | 32 字符 | 随机十六进制字符串");
    println!("Random64   | 64 字符 | 随机十六进制字符串（更长）");
    println!("Hash       | 64 字符 | SHA256 哈希，包含用户信息");
    println!("Timestamp  | ~30字符 | 包含时间信息，便于追溯");
    println!("Tik        | 8 字符  | 短小精悍，适合分享链接");
    println!("JWT        | 变长    | 包含完整信息的自包含令牌\n");

    println!("========================================");
    println!("✅ 所有 Token 风格演示完成！");
    println!("========================================");
    Ok(())
}
