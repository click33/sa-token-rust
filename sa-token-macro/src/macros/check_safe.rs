// Author: 金书记 | Author: Jin Shuji
//! Second-factor (safe) auth check macro | 二级认证检查宏

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

use crate::utils::expand_checked_fn;

pub(crate) fn sa_check_safe_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let service = if attr.is_empty() {
        syn::LitStr::new("", proc_macro2::Span::call_site())
    } else {
        parse_macro_input!(attr as syn::LitStr)
    };
    let input = parse_macro_input!(item as ItemFn);
    expand_checked_fn(
        &input,
        quote! {
            sa_token_core::StpUtil::check_safe(#service).await?;
        },
    )
}
