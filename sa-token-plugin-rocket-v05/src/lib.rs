//! Rocket **0.5.x** binding: Fairings, Guards, adapters, **`run_auth_flow`** with owned request snapshot.
//! Rocket **0.5.x** 绑定：Fairing、Guard、适配器；通过 **`run_auth_flow`** 与请求**快照**（避免跨 `await` 借用）。

#![allow(missing_docs, missing_debug_implementations)]

pub use sa_token_core::router::{AuthFlowResult, PathAuthConfig, run_auth_flow};
pub use sa_token_plugin_common::{SaLoginId, SaTokenState, SaTokenStateBuilder};

pub mod adapter;
pub mod extractor;
pub mod layer;
pub mod middleware;

pub use adapter::{RocketRequestAdapter, RocketResponseAdapter};
pub use extractor::{LoginIdGuard, OptionalSaTokenGuard, SaCtx, SaTokenGuard};
pub use layer::SaTokenLayer;
pub use middleware::{
    SaCheckLoginFairing, SaCheckPermissionFairing, SaCheckRoleFairing, SaTokenFairing,
};

pub use sa_token_adapter::{plugin::SaTokenPlugin, storage::SaStorage};
pub use sa_token_core::{self, prelude::*};
pub use sa_token_macro::*;

#[cfg(feature = "memory")]
pub use sa_token_storage_memory::MemoryStorage;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::RedisStorage;

#[cfg(feature = "database")]
pub use sa_token_storage_database::DatabaseStorage;
