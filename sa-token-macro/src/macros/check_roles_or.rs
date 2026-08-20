// Author: 金书记 | Author: Jin Shuji
//! OR role check | 多角色 OR 检查

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

use crate::utils::{expand_checked_fn, parse_nonempty_str_list, resolve_login_id_tokens};

pub(crate) fn sa_check_roles_or_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let role_lits = match parse_nonempty_str_list(attr, "At least one role is required") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let input = parse_macro_input!(item as ItemFn);
    let login_id = resolve_login_id_tokens();
    expand_checked_fn(
        &input,
        quote! {
            #login_id
            sa_token_core::StpUtil::check_any_role(&__sa_login_id, &[#(#role_lits),*]).await?;
        },
    )
}
