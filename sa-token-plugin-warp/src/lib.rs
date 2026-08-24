// Author: 金书记
//
// 中文 | English
// Warp 框架集成 | Warp Framework Integration
//
//! # sa-token-plugin-warp
//!
//! Warp框架集成插件 - 一站式认证授权解决方案
//! Warp framework integration plugin - One-stop authentication and authorization solution
//!
//! ## 快速开始 | Quick Start
//!
//! 只需要导入这一个包，即可使用所有功能：
//! Just import this package to use all features:
//!
//! ```toml
//! [dependencies]
//! sa-token-plugin-warp = "0.1.8"  # 默认使用内存存储 | Default using memory storage
//! # 或者使用 Redis 存储 | Or use Redis storage
//! sa-token-plugin-warp = { version = "0.1.8", features = ["redis"] }
//! ```
//!
//! ## 使用示例 | Usage Example
//!
//! ```rust,ignore
//! use warp::Filter;
//! use std::sync::Arc;
//! use sa_token_plugin_warp::*;  // 一次性导入所有功能 | Import all features at once
//!
//! #[tokio::main]
//! async fn main() {
//!     // 1. 初始化（使用内存存储） | Initialize (using memory storage)
//!     let state = SaTokenState::builder()
//!         .storage(Arc::new(MemoryStorage::new()))
//!         .timeout(7200)
//!         .build();
//!     
//!     // 2. 创建路由 | Create routes
//!     
//!     // 公共路由 | Public routes
//!     let login_route = warp::path!("login")
//!         .and(warp::post())
//!         .and_then(login_handler);
//!     
//!     // 需要登录的路由 | Routes requiring login
//!     let user_route = warp::path!("api" / "user" / "info")
//!         .and(sa_token_layer(state.clone()))
//!         .and(with_auth(state.clone()))
//!         .and_then(user_info_handler)
//!         .with(sa_token_cleanup());
//!     
//!     // 需要特定权限的路由 | Routes requiring specific permission
//!     let admin_route = warp::path!("api" / "admin")
//!         .and(sa_token_layer(state.clone()))
//!         .and(with_permission(state.clone(), "admin:access"))
//!         .and_then(admin_handler)
//!         .with(sa_token_cleanup());
//!     
//!     // 组合路由 | Combine routes
//!     let routes = login_route
//!         .or(user_route)
//!         .or(admin_route)
//!         .recover(handle_rejection);
//!     
//!     warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
//! }
//! ```

#![allow(missing_docs, missing_debug_implementations)]

#[cfg(not(feature = "warp-03"))]
compile_error!("sa-token-plugin-warp: enable feature `warp-03` (default).");

pub mod adapter;
pub mod extractor;
pub mod filter;
pub mod layer;
pub mod middleware;
pub mod snapshot;

// ============================================================================
// Warp 框架集成（本插件特有） | Warp framework integration (plugin specific)
// ============================================================================
pub use adapter::{WarpRequestAdapter, WarpResponseAdapter};
pub use extractor::{
    AuthError, LoginIdExtractor, OptionalSaTokenExtractor, PermissionError, RoleError,
    SaTokenExtractor, handle_rejection,
};
pub use filter::{
    TokenData, extract_login_id, extract_optional_token_value, extract_token_value,
    sa_check_login_filter, sa_token_filter,
};
pub use layer::{
    SaTokenRejection, extract_token_from_request, handle_sa_rejection, sa_check_login,
    sa_check_permission, sa_check_role, sa_token_cleanup, sa_token_layer, with_sa_token_scope,
};
pub use middleware::{
    require_auth, require_permission, require_role, with_auth, with_permission, with_role,
};
pub use sa_token_plugin_common as common;
pub use sa_token_plugin_common::{SaTokenState, SaTokenStateBuilder};
pub use snapshot::WarpRequestSnapshot;

pub use sa_token_adapter::{self, plugin::SaTokenPlugin, storage::SaStorage};
pub use sa_token_core::{self, prelude::*};
pub use sa_token_macro::*;

// ============================================================================
// 重新导出存储实现（根据 feature 条件编译） | Re-export storage implementations (feature-gated)
// ============================================================================

/// 内存存储（默认启用） | Memory storage (enabled by default)
#[cfg(feature = "memory")]
pub use sa_token_storage_memory::MemoryStorage;

/// Redis 存储 | Redis storage
#[cfg(feature = "redis")]
pub use sa_token_storage_redis::RedisStorage;

/// 数据库存储 | Database storage
#[cfg(feature = "database")]
pub use sa_token_storage_database::DatabaseStorage;
