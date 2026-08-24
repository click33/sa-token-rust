// Author: 金书记 | Author: Jin Shuji
//! Terminal / device-type check macro | 终端/设备类型检查宏

use proc_macro::TokenStream;
use quote::quote;
use syn::{Error, ItemFn, LitStr, parse_macro_input};

use crate::utils::expand_checked_fn;

pub(crate) fn sa_check_terminal_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let terminal_lit = parse_macro_input!(attr as LitStr);
    let expected = terminal_lit.value();
    if expected.trim().is_empty() {
        return Error::new_spanned(&terminal_lit, "Terminal type cannot be empty")
            .to_compile_error()
            .into();
    }
    let input = parse_macro_input!(item as ItemFn);
    expand_checked_fn(
        &input,
        quote! {
            sa_token_core::StpUtil::check_current_terminal(#expected).await?;
        },
    )
}
