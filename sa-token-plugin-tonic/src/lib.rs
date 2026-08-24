// Author: 金书记
//
// 中文 | English
// sa-token-plugin-tonic 插件主入口 | sa-token-plugin-tonic plugin main entry point
//
//! # sa-token-plugin-tonic
//!
//! 中文: Tonic gRPC 框架集成插件
//! English: Tonic gRPC framework integration for sa-token-rust
//!
//! ## 功能特性 | Features
//!
//! 中文: 提供 gRPC 服务的认证和授权支持
//! English: Provides authentication and authorization support for gRPC services built with the Tonic framework
//!
//! ## 特性列表 | Feature List
//!
//! - **Tower 鉴权层 | Tower Auth Layer**: 推荐方式，支持异步 `run_auth_flow` + `PathAuthConfig`
//! - **gRPC 拦截器 | gRPC Interceptors**: 备选方式，使用 `block_in_place` 同步执行鉴权
//! - **请求适配 | Request Adaptation**: 将 gRPC metadata 转换为 Sa-Token 请求
//! - **状态管理 | State Management**: 跨所有 gRPC 服务共享状态
//! - **权限检查 | Permission Checking**: 内置角色和权限验证辅助函数
//! - **错误类型 | Error Types**: gRPC 专用认证错误类型
//!
//! ## 使用示例 | Usage Example
//!
//! ```rust,ignore
//! use sa_token_plugin_tonic::{SaTokenState, SaTokenGrpcLayer, PathAuthConfig, MemoryStorage};
//! use std::sync::Arc;
//!
//! let state = SaTokenState::builder()
//!     .storage(Arc::new(MemoryStorage::new()))
//!     .timeout(7200)
//!     .build();
//!
//! let path_config = PathAuthConfig::new()
//!     .include(vec!["/auth.AuthService/**".to_string()])
//!     .exclude(vec!["/auth.AuthService/Login".to_string()]);
//!
//! let layer = SaTokenGrpcLayer::with_path_auth(state, path_config);
//! ```

#![allow(missing_docs, missing_debug_implementations)]

#[cfg(not(feature = "tonic-012"))]
compile_error!("sa-token-plugin-tonic: enable feature `tonic-012` (default).");

// 中文: 公开模块 | English: Public modules
pub mod adapter;
pub mod error;
pub mod interceptor;
pub mod layer;

// 中文: 公开类型导出 | English: Public type exports
pub use adapter::{TonicCapturedRequest, TonicRequestAdapter, TonicResponseAdapter};
pub use error::{
    AuthError, GrpcTokenData, PermissionError, SaTokenBearerToken, SaTokenGrpcPath, SaTokenLoginId,
};
pub use interceptor::{
    GrpcServerInterceptor, check_permission, check_permissions, check_role, check_roles,
    create_request_adapter, get_bearer_token_from_request, get_login_id_from_request,
    validate_token_from_request,
};
pub use layer::{SaTokenGrpcLayer, SaTokenGrpcMiddleware};
pub use sa_token_plugin_common as common;
pub use sa_token_plugin_common::{SaTokenState, SaTokenStateBuilder};

// 中文: 重导出 core router（与 Axum/Salvo 一致）| English: Re-export core router
pub use sa_token_core::router::{AuthFlowResult, PathAuthConfig, run_auth_flow};

// 中文: 重新导出核心依赖 | English: Re-export core dependencies
pub use sa_token_adapter::{self, plugin::SaTokenPlugin, storage::SaStorage};
pub use sa_token_core::{self, prelude::*};
pub use sa_token_macro::*;

// 中文: 根据特性条件编译存储实现 | English: Storage implementations with feature gates
#[cfg(feature = "memory")]
pub use sa_token_storage_memory::MemoryStorage;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::RedisStorage;

#[cfg(feature = "database")]
pub use sa_token_storage_database::DatabaseStorage;
