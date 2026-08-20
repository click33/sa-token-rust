//! Facade: pinned Salvo semver via `*-v*` binding crate / 门面：通过 `*-v*` 绑定固定 Salvo 大版本。
//!
//! - **`v079`** (default | 默认): `sa-token-plugin-salvo-v079` — Salvo **0.79.x**.

#![allow(missing_docs, missing_debug_implementations)]

#[cfg(not(feature = "v079"))]
compile_error!("sa-token-plugin-salvo: enable `v079` (default).");

#[cfg(feature = "v079")]
pub use sa_token_plugin_salvo_v079::*;
