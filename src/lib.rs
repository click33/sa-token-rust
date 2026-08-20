// Author: 金书记
//
//! sa-token-rust 根 crate：聚合 re-export 常用 API，便于 `cargo add sa-token-rust` 后快速上手。
//!
//! 框架集成请选用对应 plugin crate（如 `sa-token-plugin-axum`）。

pub use sa_token_adapter as adapter;
pub use sa_token_core as core;
pub use sa_token_macro as macro_exports;

// 核心门面：覆盖 80% 入门场景的 type 与入口
pub use sa_token_core::{
    SaLogic, SaSession, SaTerminalInfo, SaTokenConfig, SaTokenContext, SaTokenError,
    SaTokenManager, SaTokenResult, StpUtil, TokenInfo, TokenValue,
};

#[cfg(feature = "fory")]
pub use sa_token_adapter::serializer::ForySerializer;
pub use sa_token_core::{JsonSerializer, SaSerializer, SharedSerializer, ValueKind};

// 存储后端按 feature 可选 re-export，避免默认拉入 redis/sqlx
#[cfg(feature = "database")]
pub use sa_token_storage_database::DatabaseStorage;
#[cfg(feature = "memory")]
pub use sa_token_storage_memory::MemoryStorage;
#[cfg(feature = "redis")]
pub use sa_token_storage_redis::RedisStorage;
