//! Actix-web **4.x** binding: middleware + layer call **`run_auth_flow`** with **`ActixRequestAdapter`** (borrows `HttpRequest`, valid inside the service `call` future).
//! Actix-web **4.x** 绑定：中间件与 Layer 用 **`ActixRequestAdapter`**（借 `HttpRequest`）在 **`run_auth_flow`** 中完成鉴权流水线。

#![allow(missing_docs, missing_debug_implementations)]

pub use sa_token_core::router::{AuthFlowResult, PathAuthConfig, run_auth_flow};
pub use sa_token_plugin_common as common;
pub use sa_token_plugin_common::{SaTokenState, SaTokenStateBuilder};

pub mod adapter;
pub mod error_response;
pub mod ext;
pub mod extractor;
pub mod layer;
pub mod middleware;

pub use adapter::{ActixRequestAdapter, ActixResponseAdapter};
pub use error_response::sa_token_error_response;
pub use ext::{SaTokenData, into_data};
pub use extractor::{LoginIdExtractor, OptionalSaTokenExtractor, SaTokenExtractor};
pub use layer::SaTokenLayer;
pub use middleware::{SaCheckLoginMiddleware, SaTokenMiddleware};

pub use sa_token_adapter::{plugin::SaTokenPlugin, storage::SaStorage};
pub use sa_token_core::{self, prelude::*};
pub use sa_token_macro::*;

#[cfg(feature = "memory")]
pub use sa_token_storage_memory::MemoryStorage;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::RedisStorage;

#[cfg(feature = "database")]
pub use sa_token_storage_database::DatabaseStorage;
