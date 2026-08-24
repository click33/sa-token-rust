// Author: 金书记 | Author: Jin Shuji
//! Same-Token check macro | Same-Token 检查宏

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

use crate::utils::expand_checked_fn;

pub(crate) fn sa_check_same_token_impl(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    expand_checked_fn(
        &input,
        quote! {
            sa_token_core::same_token::check_current_request().await?;
        },
    )
}
