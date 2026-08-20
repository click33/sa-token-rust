// Author: 金书记 | Author: Jin Shuji
//
//! Login check macro: insert async storage-backed login verification.
//! 登录检查宏：插入基于存储的异步登录校验。
//!
//! Middleware fills `SaTokenContext`; this macro calls `check_login_current_async`.
//! 中间件填充 `SaTokenContext`；本宏调用 `check_login_current_async`。

use proc_macro::TokenStream;
use syn::{ItemFn, parse_macro_input};

use crate::utils::{check_login_async_tokens, expand_checked_fn};

pub(crate) fn sa_check_login_impl(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let auth_check = check_login_async_tokens();
    expand_checked_fn(&input, auth_check)
}
