// Author: 金书记
//
//! Gotham **0.7.x** binding / Gotham **0.7.x** 绑定：**`GothamCapturedRequest`** + **`run_auth_flow`**; `StateData` wrappers in **`wrapper`**.
//! **`GothamCapturedRequest`** + **`run_auth_flow`**；**`wrapper`** 中提供 **`StateData`** 包装类型。

#![allow(missing_docs, missing_debug_implementations)]

pub use sa_token_core::router::{AuthFlowResult, PathAuthConfig, run_auth_flow};
pub use sa_token_plugin_common::{SaLoginId, SaTokenState, SaTokenStateBuilder};

pub mod adapter;
pub mod extractor;
pub mod layer;
pub mod middleware;
pub mod wrapper;

pub use sa_token_adapter::{plugin::SaTokenPlugin, storage::SaStorage};
pub use sa_token_core::{self, prelude::*};
pub use sa_token_macro::*;

#[cfg(feature = "memory")]
pub use sa_token_storage_memory::*;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::*;

#[cfg(feature = "database")]
pub use sa_token_storage_database::*;

pub use adapter::*;
pub use extractor::*;
pub use layer::SaTokenLayer;
#[allow(deprecated)]
pub use middleware::{
    AuthMiddleware, SaCheckLoginMiddleware, SaCheckPermissionMiddleware, SaCheckRoleMiddleware,
    SaTokenMiddleware,
};
pub use wrapper::{LoginIdWrapper, TokenValueWrapper};
