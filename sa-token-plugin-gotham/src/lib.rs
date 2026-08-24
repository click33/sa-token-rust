//! Facade: pinned Gotham **0.7** line / 门面：固定 Gotham **0.7** 线。
//!
//! - **`v074`** (default | 默认): `sa-token-plugin-gotham-v074` — Gotham **0.7.x**.

#![allow(missing_docs, missing_debug_implementations)]

#[cfg(not(feature = "v074"))]
compile_error!("sa-token-plugin-gotham: enable `v074` (default).");

#[cfg(feature = "v074")]
pub use sa_token_plugin_gotham_v074::*;
