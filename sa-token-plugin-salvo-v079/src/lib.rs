// Author: 金书记
//
//! Salvo **0.79.x** binding: `Handler`-style **`SaTokenLayer`**, **`SalvoCapturedRequest`** snapshot before `await`, optional **`PathAuthConfig`**.
//! Salvo **0.79.x** 绑定：`Handler` 式 **`SaTokenLayer`**、`await` 前 **`SalvoCapturedRequest`** 快照、可选 **`PathAuthConfig`**。

#![allow(missing_docs, missing_debug_implementations)]

pub use sa_token_core::router::{AuthFlowResult, PathAuthConfig, run_auth_flow};
pub use sa_token_plugin_common::{SaLoginId, SaTokenState, SaTokenStateBuilder};

pub mod adapter;
pub mod extractor;
pub mod layer;
pub mod middleware;

pub use adapter::*;
pub use extractor::*;
pub use layer::{SaTokenLayer, extract_token_from_request};
pub use middleware::{
    SaCheckLoginMiddleware, SaCheckPermissionMiddleware, SaCheckRoleMiddleware, auth_middleware,
    permission_middleware,
};

pub use sa_token_adapter::{self, plugin::SaTokenPlugin, storage::SaStorage};
pub use sa_token_core::{self, prelude::*};
pub use sa_token_macro::*;

#[cfg(feature = "memory")]
pub use sa_token_storage_memory::*;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::*;

#[cfg(feature = "database")]
pub use sa_token_storage_database::*;
