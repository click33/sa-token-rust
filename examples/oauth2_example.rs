//! OAuth2 授权码模式示例
//!
//! 演示完整的 OAuth2 授权流程
//!
//! ## 导入方式
//!
//! ### 方式1: 独立使用核心库（本示例）
//! ```ignore
//! use sa_token_core::{OAuth2Manager, OAuth2Client};
//! ```
//!
//! ### 方式2: 使用 Web 框架插件（推荐）
//! ```toml
//! [dependencies]
//! sa-token-plugin-axum = "0.1.3"
//! ```
//! ```ignore
//! use sa_token_plugin_axum::*;  // OAuth2 相关类型已重新导出！
//! ```

#![allow(clippy::print_stdout, clippy::print_stderr)]

use sa_token_core::{OAuth2Client, OAuth2Manager};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("========================================");
    println!("OAuth2 授权码模式示例 | OAuth2 Authorization Code Flow Example");
    println!("========================================\n");

    let storage = Arc::new(MemoryStorage::new());
    let oauth2 = OAuth2Manager::new(storage).with_ttl(600, 3600, 2592000);

    println!(">>> 步骤 1: 注册 OAuth2 客户端 | Step 1: Register OAuth2 Client\n");

    let plain_secret = "secret_abc123xyz";
    let client = OAuth2Client {
        client_id: "web_app_001".to_string(),
        client_secret: String::new(),
        client_secret_hash: String::new(),
        redirect_uris: vec![
            "http://localhost:3000/callback".to_string(),
            "http://localhost:3000/auth/callback".to_string(),
        ],
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        scope: vec![
            "read".to_string(),
            "write".to_string(),
            "profile".to_string(),
        ],
        public_client: false,
    };

    oauth2
        .register_client_with_secret(client.clone(), plain_secret)
        .await?;

    println!("客户端信息:");
    println!("  Client ID: {}", client.client_id);
    println!(
        "  Client Secret (plaintext, in-memory only): {}",
        plain_secret
    );
    println!("  Redirect URIs: {:?}", client.redirect_uris);
    println!("  Grant Types: {:?}", client.grant_types);
    println!("  Scopes: {:?}\n", client.scope);

    println!(">>> 步骤 2: 用户授权 - 生成授权码\n");

    let user_id = "user_10086";
    let redirect_uri = "http://localhost:3000/callback";
    let requested_scope = vec!["read".to_string(), "profile".to_string()];

    if !oauth2.validate_redirect_uri(&client, redirect_uri) {
        return Err("Invalid redirect URI".into());
    }

    if !oauth2.validate_scope(&client, &requested_scope) {
        return Err("Invalid scope".into());
    }

    let auth_code = oauth2.generate_authorization_code(
        client.client_id.clone(),
        user_id.to_string(),
        redirect_uri.to_string(),
        requested_scope.clone(),
        None,
        None,
    );

    println!("授权码信息:");
    println!("  Code: {}", auth_code.code);
    println!("  User ID: {}", auth_code.user_id);
    println!("  Client ID: {}", auth_code.client_id);
    println!("  Redirect URI: {}", auth_code.redirect_uri);
    println!("  Scope: {:?}", auth_code.scope);
    println!("  Expires At: {}\n", auth_code.expires_at);

    oauth2.store_authorization_code(&auth_code).await?;
    println!("✓ 授权码已存储\n");

    println!(">>> 步骤 3: 用授权码换取访问令牌\n");

    let access_token = oauth2
        .exchange_code_for_token(
            &auth_code.code,
            &client.client_id,
            plain_secret,
            redirect_uri,
            None,
        )
        .await?;

    println!("访问令牌:");
    println!("  Access Token: {}", access_token.access_token);
    println!("  Token Type: {}", access_token.token_type);
    println!("  Expires In: {} 秒", access_token.expires_in);
    println!(
        "  Refresh Token: {}",
        access_token.refresh_token.as_ref().unwrap()
    );
    println!("  Scope: {:?}\n", access_token.scope);

    println!(">>> 步骤 4: 验证访问令牌\n");

    let token_info = oauth2
        .verify_access_token(&access_token.access_token)
        .await?;

    println!("令牌信息:");
    println!("  User ID: {}", token_info.user_id);
    println!("  Client ID: {}", token_info.client_id);
    println!("  Scope: {:?}", token_info.scope);
    println!("  Expires At: {}\n", token_info.expires_at);

    println!(">>> 步骤 5: 使用刷新令牌获取新的访问令牌\n");

    let refresh_token = access_token.refresh_token.as_ref().unwrap();
    let new_access_token = oauth2
        .refresh_access_token(refresh_token, &client.client_id, plain_secret)
        .await?;

    println!("新访问令牌:");
    println!("  Access Token: {}", new_access_token.access_token);
    println!("  Token Type: {}", new_access_token.token_type);
    println!("  Expires In: {} 秒", new_access_token.expires_in);
    println!(
        "  Refresh Token: {}\n",
        new_access_token.refresh_token.as_ref().unwrap()
    );

    println!(">>> 步骤 6: 撤销令牌\n");

    oauth2.revoke_token(&new_access_token.access_token).await?;
    println!("✓ 令牌已撤销\n");

    match oauth2
        .verify_access_token(&new_access_token.access_token)
        .await
    {
        Ok(_) => println!("✗ 令牌仍然有效（不应该）"),
        Err(_) => println!("✓ 令牌已失效（预期结果）\n"),
    }

    println!("========================================");
    println!("OAuth2 授权流程完成");
    println!("========================================\n");

    println!("完整流程:");
    println!("  1. 注册客户端 ✓");
    println!("  2. 生成授权码 ✓");
    println!("  3. 授权码换令牌 ✓");
    println!("  4. 验证访问令牌 ✓");
    println!("  5. 刷新访问令牌 ✓");
    println!("  6. 撤销令牌 ✓");

    Ok(())
}
