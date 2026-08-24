// Author: 金书记
//
// 中文 | English
// Tide 框架集成 | Tide Framework Integration
//
//! # sa-token-plugin-tide
//!
//! 为 Tide 框架提供 sa-token 认证和授权支持
//! Provides sa-token authentication and authorization support for Tide framework
//!
//! ## 特性 | Features
//!
//! - ✨ 一行导入所有功能 | One-line import for all functionalities
//! - 🔧 支持多种存储后端 | Support for multiple storage backends
//! - 🚀 简化的中间件集成 | Simplified middleware integration
//! - 📦 包含核心、宏、存储 | Includes core, macros, and storage
//!
//! ## 快速开始 | Quick Start
//!
//! ```toml
//! [dependencies]
//! sa-token-plugin-tide = "0.1.8"
//! ```
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use sa_token_plugin_tide::*;
//!
//! #[async_std::main]
//! async fn main() -> tide_017::Result<()> {
//!     let storage = Arc::new(MemoryStorage::new());
//!     
//!     // 创建 Sa-Token 状态 | Create Sa-Token state
//!     let state = SaTokenState::builder()
//!         .token_name("Authorization")
//!         .timeout(7200)
//!         .storage(storage)
//!         .build();
//!     
//!     let mut app = tide_017::new();
//!     
//!     // 公共路由 | Public routes
//!     app.at("/login").post(login_handler);
//!     
//!     // 需要登录的路由 | Routes requiring login
//!     app.at("/user")
//!         .with(SaCheckLoginMiddleware::new(state.clone()))
//!         .get(user_info_handler);
//!     
//!     // 需要特定权限的路由 | Routes requiring specific permission
//!     app.at("/admin")
//!         .with(SaCheckPermissionMiddleware::new(state.clone(), "admin:access"))
//!         .get(admin_handler);
//!     
//!     app.listen("127.0.0.1:8080").await?;
//!     Ok(())
//! }
//! ```

#![allow(missing_docs, missing_debug_implementations)]

#[cfg(not(feature = "tide-017"))]
compile_error!("sa-token-plugin-tide: enable feature `tide-017` (default).");

pub mod adapter;
pub mod extractor;
pub mod layer;
pub mod middleware;

pub use sa_token_plugin_common as common;
pub use sa_token_plugin_common::{SaTokenState, SaTokenStateBuilder};

pub use sa_token_adapter::{self, plugin::SaTokenPlugin, storage::SaStorage};
pub use sa_token_core::{self, prelude::*};
pub use sa_token_macro::*;

// 重新导出存储实现（通过 feature 控制）
// Re-export storage implementations (controlled by features)
#[cfg(feature = "memory")]
pub use sa_token_storage_memory::*;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::*;

#[cfg(feature = "database")]
pub use sa_token_storage_database::*;

// 重新导出本模块的适配器 | Re-export adapters from this module
pub use adapter::*;
pub use extractor::*;
pub use layer::{SaTokenLayer, extract_token_from_request};
pub use middleware::{
    AuthMiddleware, PermissionMiddleware, SaCheckLoginMiddleware, SaCheckPermissionMiddleware,
    SaCheckRoleMiddleware,
};
