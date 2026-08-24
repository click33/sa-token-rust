// Author: 金书记 | Author: Jin Shuji
//! Role check macro | 角色检查宏

use proc_macro::TokenStream;
use quote::quote;
use syn::{Error, ItemFn, LitStr, parse_macro_input};

use crate::utils::{expand_checked_fn, resolve_login_id_tokens};

pub(crate) fn sa_check_role_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let role = parse_macro_input!(attr as LitStr);
    let role_value = role.value();
    if role_value.trim().is_empty() {
        return Error::new_spanned(&role, "Role name cannot be empty")
            .to_compile_error()
            .into();
    }
    let input = parse_macro_input!(item as ItemFn);
    let login_id = resolve_login_id_tokens();
    expand_checked_fn(
        &input,
        quote! {
            #login_id
            sa_token_core::StpUtil::check_role(&__sa_login_id, #role_value).await?;
        },
    )
}
