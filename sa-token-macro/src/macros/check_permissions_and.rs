// Author: 金书记 | Author: Jin Shuji
//! AND permission check | 多权限 AND 检查

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

use crate::utils::{expand_checked_fn, parse_nonempty_str_list, resolve_login_id_tokens};

pub(crate) fn sa_check_permissions_and_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let perm_lits = match parse_nonempty_str_list(attr, "At least one permission is required") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let input = parse_macro_input!(item as ItemFn);
    let login_id = resolve_login_id_tokens();
    expand_checked_fn(
        &input,
        quote! {
            #login_id
            sa_token_core::StpUtil::check_all_permissions(&__sa_login_id, &[#(#perm_lits),*]).await?;
        },
    )
}
