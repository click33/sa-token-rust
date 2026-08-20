//! Facade: selects the Rocket semver binding crate via features.
//! 门面：通过 feature 选择 Rocket 语义版本绑定 crate。
//!
//! - **`v05`** (default | 默认): `sa-token-plugin-rocket-v05` — Rocket **0.5.x**.

#![allow(missing_docs, missing_debug_implementations)]

#[cfg(not(feature = "v05"))]
compile_error!("sa-token-plugin-rocket: enable `v05` (default).");

#[cfg(feature = "v05")]
pub use sa_token_plugin_rocket_v05::*;
