// Author: 金书记
//
//! # sa-token-adapter
//!
//! 适配器trait定义，用于实现框架无关的抽象层
//!
//! 这个crate定义了所有需要适配的接口，包括：
//! - 存储适配器
//! - 请求/响应上下文适配器
//! - 框架集成适配器

pub mod context;
pub mod counting;
pub mod plugin;
pub mod serializer;
pub mod storage;
/// Cookie / Bearer / query helpers | Cookie、Bearer、查询串辅助函数
pub mod utils;

pub use context::{CookieOptions, SaRequest, SaResponse, SameSite};
pub use counting::CountingStorage;
pub use plugin::SaTokenPlugin;
pub use serializer::{
    BINARY_MAGIC, JsonSerializer, JsonSerializerConfig, SaSerializer, SerializerError,
    SharedSerializer, ValueKind,
};
#[cfg(feature = "fory")]
pub use serializer::{ForySerializer, ForySerializerConfig};
pub use storage::{
    SaStorage, ScanPage, StorageError, StorageResult, scan_all_keys, scan_all_keys_dedup,
};
pub use utils::{
    build_cookie_string, extract_bearer_or_value, parse_cookies, parse_query_string,
    strip_bearer_or_passthrough, strip_bearer_prefix,
};

/// 向后兼容；新代码请用 [`strip_bearer_prefix`](utils::strip_bearer_prefix) 或 [`extract_bearer_or_value`](utils::extract_bearer_or_value)。
#[allow(deprecated)]
pub use utils::extract_bearer_token;
