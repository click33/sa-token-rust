// Author: 金书记
//
//! Sa-Token 配置初始化
//! Sa-Token Configuration Initialization

use std::sync::Arc;
use anyhow::Result;
use sa_token_plugin_actix_web::*;

/// Redis配置
/// Redis Configuration
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: String,
    pub prefix: Option<String>,
}

/// 初始化 Sa-Token
/// Initialize Sa-Token
/// 
/// 如果提供了 Redis 配置，则使用 Redis 存储
/// If Redis configuration is provided, use Redis storage
/// 否则使用内存存储
/// Otherwise use memory storage
pub async fn init_sa_token(redis_config: Option<&RedisConfig>) -> Result<Arc<SaTokenManager>> {
    // 创建配置构建器
    // Create configuration builder
    let mut config_builder = SaTokenConfig::builder()
        .token_name("Authorization")
        .timeout(86400)  // 24小时 / 24 hours
        .token_style(TokenStyle::Random64)
        .auto_renew(true);
    
    // 根据配置选择存储方式
    // Choose storage method based on configuration
    if let Some(_redis_cfg) = redis_config {
        #[cfg(feature = "redis")]
        {
            use sa_token_plugin_actix_web::RedisStorage;
            use sa_token_storage_redis::RedisConfig;
            
            let redis_storage = RedisStorage::new(RedisConfig {
                url: _redis_cfg.url.clone(),
                prefix: _redis_cfg.prefix.clone().unwrap_or_default(),
            }).await?;
            
            config_builder = config_builder.storage(Arc::new(redis_storage));
            tracing::info!("使用 Redis 存储: {}", _redis_cfg.url);
            tracing::info!("Using Redis storage: {}", _redis_cfg.url);
        }
        
        #[cfg(not(feature = "redis"))]
        {
            tracing::warn!("Redis 功能未启用，回退到内存存储");
            tracing::warn!("Redis feature not enabled, falling back to memory storage");
            config_builder = config_builder.storage(Arc::new(MemoryStorage::new()));
        }
    } else {
        // 使用内存存储
        // Use memory storage
        config_builder = config_builder.storage(Arc::new(MemoryStorage::new()));
        tracing::info!("使用内存存储");
        tracing::info!("Using memory storage");
    }
    
    // 构建 SaTokenManager
    // Build SaTokenManager
    let manager = config_builder.build();
    
    Ok(Arc::new(manager))
}
