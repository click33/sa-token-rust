//! Facade crate: re-exports exactly one Actix-web binding at compile time.
//! 门面 crate：编译期只重导出 **一个** Actix-web 版本绑定。
//!
//! - **`v4`** (default | 默认): `sa_token_plugin_actix_web_v4` — actix-web **4.x**.
//! - **`v5`**: placeholder only; enabling **only** `v5` triggers **`compile_error!`** on this crate.
//!   **`v5`**：仅占位；仅启用 **`v5`** 时在本 crate 上触发 **`compile_error!`**。

#![allow(missing_docs, missing_debug_implementations)]

#[cfg(all(feature = "v4", feature = "v5"))]
compile_error!("sa-token-plugin-actix-web: enable exactly one of `v4` / `v5`.");

#[cfg(not(any(feature = "v4", feature = "v5")))]
compile_error!("sa-token-plugin-actix-web: enable one of `v4` or `v5` (default: v4).");

#[cfg(all(feature = "v5", not(feature = "v4")))]
compile_error!(
    "sa-token-plugin-actix-web: actix-web 5.x (`v5`) is not implemented yet. \
     Use default `v4`."
);

#[cfg(feature = "v4")]
pub use sa_token_plugin_actix_web_v4::*;
