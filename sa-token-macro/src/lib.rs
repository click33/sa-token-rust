// Author: 金书记 | Author: Jin Shuji
//
//! # sa-token-macro
//!
//! Procedural macros that insert authentication checks at the start of async handlers.
//! 在 async 处理函数开头插入认证检查的过程宏。
//!
//! Annotated functions must be `async fn` returning `Result<T, E>` where
//! `E: From<sa_token_core::SaTokenError>`.
//! 被标注函数必须是返回 `Result<T, E>` 的 `async fn`。
//!
//! Middleware extracts the token and fills `SaTokenContext`; macros call `StpUtil`.
//! 中间件提取 token 并填充上下文；宏调用 `StpUtil`。
//!
//! `#[sa_ignore]` does not skip middleware — use `PathAuthConfig::exclude`.
//! `#[sa_ignore]` 不会跳过中间件 — 请使用 `PathAuthConfig::exclude`。
//!
//! ## Examples
//!
//! ```rust,ignore
//! use sa_token_core::{SaTokenError, SaTokenResult};
//! use sa_token_macro::*;
//!
//! #[sa_check_login]
//! async fn user_info() -> SaTokenResult<&'static str> {
//!     Ok("User info")
//! }
//!
//! #[sa_check_permission("user:delete")]
//! async fn delete_user(id: u64) -> Result<&'static str, SaTokenError> {
//!     let _ = id;
//!     Ok("User deleted")
//! }
//!
//! #[sa_check_role("admin")]
//! async fn admin_panel() -> SaTokenResult<&'static str> {
//!     Ok("Admin panel")
//! }
//!
//! #[sa_check_terminal("pc")]
//! async fn pc_only() -> SaTokenResult<&'static str> {
//!     Ok("PC only")
//! }
//!
//! #[sa_check_http_basic("admin:secret")]
//! async fn basic_protected() -> SaTokenResult<&'static str> {
//!     Ok("Basic ok")
//! }
//!
//! #[sa_check_same_token]
//! async fn internal_call() -> SaTokenResult<&'static str> {
//!     Ok("Same-token ok")
//! }
//!
//! #[sa_ignore]
//! async fn public_api() -> &'static str {
//!     // Does not insert StpUtil checks; still use PathAuthConfig::exclude for middleware.
//!     "Public API"
//! }
//! ```

use proc_macro::TokenStream;

mod macros;
mod utils;

use macros::{
    check_disable::sa_check_disable_impl, check_http_basic::sa_check_http_basic_impl,
    check_login::sa_check_login_impl, check_or::sa_check_or_impl,
    check_permission::sa_check_permission_impl,
    check_permissions_and::sa_check_permissions_and_impl,
    check_permissions_or::sa_check_permissions_or_impl, check_role::sa_check_role_impl,
    check_roles_and::sa_check_roles_and_impl, check_roles_or::sa_check_roles_or_impl,
    check_safe::sa_check_safe_impl, check_same_token::sa_check_same_token_impl,
    check_terminal::sa_check_terminal_impl, ignore::sa_ignore_impl,
};

/// Check login (async, storage-backed). | 检查登录（异步、走存储）。
#[proc_macro_attribute]
pub fn sa_check_login(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_login_impl(attr, item)
}

/// Check a single permission. | 检查单个权限。
#[proc_macro_attribute]
pub fn sa_check_permission(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_permission_impl(attr, item)
}

/// Check a single role. | 检查单个角色。
#[proc_macro_attribute]
pub fn sa_check_role(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_role_impl(attr, item)
}

/// Check all listed permissions (AND). | 检查列出的全部权限（AND）。
#[proc_macro_attribute]
pub fn sa_check_permissions_and(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_permissions_and_impl(attr, item)
}

/// Check any listed permission (OR). | 检查列出的任一权限（OR）。
#[proc_macro_attribute]
pub fn sa_check_permissions_or(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_permissions_or_impl(attr, item)
}

/// Check all listed roles (AND). | 检查列出的全部角色（AND）。
#[proc_macro_attribute]
pub fn sa_check_roles_and(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_roles_and_impl(attr, item)
}

/// Check any listed role (OR). | 检查列出的任一角色（OR）。
#[proc_macro_attribute]
pub fn sa_check_roles_or(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_roles_or_impl(attr, item)
}

/// Do not insert StpUtil checks (does not skip middleware).
/// 不插入 StpUtil 检查（不跳过中间件）。
#[proc_macro_attribute]
pub fn sa_ignore(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_ignore_impl(attr, item)
}

/// Check second-factor (safe) auth. | 检查二级认证。
#[proc_macro_attribute]
pub fn sa_check_safe(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_safe_impl(attr, item)
}

/// Check account disable level. | 检查账号封禁等级。
#[proc_macro_attribute]
pub fn sa_check_disable(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_disable_impl(attr, item)
}

/// Combined OR checks. | 组合 OR 鉴权。
#[proc_macro_attribute]
pub fn sa_check_or(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_or_impl(attr, item)
}

/// Check current token device type. | 检查当前 token 设备类型。
#[proc_macro_attribute]
pub fn sa_check_terminal(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_terminal_impl(attr, item)
}

/// HTTP Basic check. | HTTP Basic 检查。
#[proc_macro_attribute]
pub fn sa_check_http_basic(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_http_basic_impl(attr, item)
}

/// Same-Token check for internal calls. | 内部调用 Same-Token 检查。
#[proc_macro_attribute]
pub fn sa_check_same_token(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_same_token_impl(attr, item)
}
