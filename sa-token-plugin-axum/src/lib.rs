// Author: 金书记
//
//! # sa-token-plugin-axum
//!
//! Axum framework integration for sa-token-rust.
//!
//! Enable **`axum-08`** (default) for Axum 0.8; dependencies use Cargo keys `axum-08` /
//! `tower-08` so additional Axum majors can be added later without renaming the crate.

#![allow(missing_docs, missing_debug_implementations)]

#[cfg(not(feature = "axum-08"))]
compile_error!(
    "sa-token-plugin-axum: enable feature `axum-08` (default). \
     Future Axum versions will be additional opt-in features."
);

pub mod shared;

pub use sa_token_plugin_common as common;
pub use sa_token_plugin_common::{SaLoginId, SaTokenState, SaTokenStateBuilder};
pub use shared::adapter::{AxumRequestAdapter, AxumRequestSnapshot, AxumResponseAdapter};

#[cfg(feature = "axum-08")]
mod v08;

#[cfg(feature = "axum-08")]
pub use v08::{
    LoginIdExtractor, OptionalSaTokenExtractor, SaCheckLoginLayer, SaCheckLoginMiddleware,
    SaCheckPermissionLayer, SaCheckPermissionMiddleware, SaTokenExtractor, SaTokenLayer,
    SaTokenMiddleware, sa_token_error_response,
};

pub use sa_token_adapter::{self, plugin::SaTokenPlugin, storage::SaStorage};
pub use sa_token_core::{self, prelude::*};
pub use sa_token_macro::*;

#[cfg(feature = "memory")]
pub use sa_token_storage_memory::MemoryStorage;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::RedisStorage;

#[cfg(feature = "database")]
pub use sa_token_storage_database::DatabaseStorage;
