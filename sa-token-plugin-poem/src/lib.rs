// Author: 金书记
//
//! # sa-token-plugin-poem
//!
//! Poem 框架集成插件 - 一站式认证授权解决方案
//!
//! ## 快速开始
//!
//! 只需要导入这一个包，即可使用所有功能：
//!
//! ```toml
//! [dependencies]
//! sa-token-plugin-poem = "0.1.3"  # 默认使用内存存储
//! # 或者使用 Redis 存储
//! sa-token-plugin-poem = { version = "0.1.3", features = ["redis"] }
//! ```
//!
//! ## 使用示例
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use poem_03::{Route, Server, listener::TcpListener, handler};
//! use sa_token_plugin_poem::*;  // 一次性导入所有功能
//!
//! #[handler]
//! async fn user_info(token: SaTokenExtractor) -> String {
//!     format!("User ID: {}", token.login_id())
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), std::io::Error> {
//!     // 1. 初始化（使用内存存储，已重新导出）
//!     let sa_token_state = SaTokenState::builder()
//!         .storage(Arc::new(MemoryStorage::new()))
//!         .timeout(7200)
//!         .build();
//!     
//!     // 2. 创建路由
//!     let app = Route::new()
//!         .at("/api/user/info", poem_03::get(user_info))
//!         .with(SaTokenMiddleware::new(sa_token_state.manager.clone()))
//!         .data(sa_token_state);
//!     
//!     // 3. 使用宏检查权限
//!     #[sa_check_login]
//!     #[handler]
//!     async fn protected() -> String {
//!         "Protected resource".to_string()
//!     }
//!     
//!     Server::new(TcpListener::bind("127.0.0.1:3000"))
//!         .run(app)
//!         .await
//! }
//! ```

#![allow(missing_docs, missing_debug_implementations)]

#[cfg(not(feature = "poem-03"))]
compile_error!("sa-token-plugin-poem: enable feature `poem-03` (default).");

pub mod adapter;
pub mod error_response;
pub mod extractor;
pub mod layer;
pub mod middleware;

// ============================================================================
// Poem 框架集成（本插件特有）
// ============================================================================
pub use adapter::{PoemRequestAdapter, PoemResponseAdapter};
pub use error_response::{sa_token_error, sa_token_error_response};
pub use extractor::{LoginIdExtractor, OptionalSaTokenExtractor, SaTokenExtractor};
pub use layer::SaTokenLayer;
pub use middleware::{SaCheckLoginMiddleware, SaTokenMiddleware};
pub use sa_token_plugin_common as common;
pub use sa_token_plugin_common::{SaTokenState, SaTokenStateBuilder};

pub use sa_token_adapter::{self, plugin::SaTokenPlugin, storage::SaStorage};
pub use sa_token_core::{self, prelude::*};
pub use sa_token_macro::*;

// ============================================================================
// 重新导出存储实现（根据 feature 条件编译）
// ============================================================================

/// 内存存储（默认启用）
#[cfg(feature = "memory")]
pub use sa_token_storage_memory::MemoryStorage;

/// Redis 存储
#[cfg(feature = "redis")]
pub use sa_token_storage_redis::RedisStorage;

/// 数据库存储
#[cfg(feature = "database")]
pub use sa_token_storage_database::DatabaseStorage;
