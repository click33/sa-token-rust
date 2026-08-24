//! Facade: pinned Ntex line via binding crate / 门面：通过绑定 crate 固定 Ntex 线。
//!
//! - **`v212`** (default | 默认): `sa-token-plugin-ntex-v212` — ntex **`2.12`** (workspace pin; Cargo may resolve compatible **2.x**).
//!   **`2.12`**（工作区 pin；Cargo 可解析兼容的 **2.x**）。

#![allow(missing_docs, missing_debug_implementations)]

#[cfg(not(feature = "v212"))]
compile_error!("sa-token-plugin-ntex: enable `v212` (default).");

#[cfg(feature = "v212")]
pub use sa_token_plugin_ntex_v212::*;
