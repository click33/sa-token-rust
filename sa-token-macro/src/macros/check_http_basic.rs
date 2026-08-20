// Author: 金书记 | Author: Jin Shuji
//! HTTP Basic check macro | HTTP Basic 检查宏
//!
//! Forms | 形式:
//! - `#[sa_check_http_basic]`
//! - `#[sa_check_http_basic("user:pass")]`
//! - `#[sa_check_http_basic(account = "user:pass", realm = "sa-token")]`

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Ident, ItemFn, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

use crate::utils::expand_checked_fn;

struct BasicAttr {
    account: String,
    realm: String,
}

impl Parse for BasicAttr {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut account = String::new();
        let mut realm = "sa-token".to_string();
        if input.is_empty() {
            return Ok(Self { account, realm });
        }
        if input.peek(LitStr) {
            account = input.parse::<LitStr>()?.value();
            return Ok(Self { account, realm });
        }
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let lit: LitStr = input.parse()?;
            if key == "account" {
                account = lit.value();
            } else if key == "realm" {
                realm = lit.value();
            } else {
                return Err(syn::Error::new_spanned(
                    key,
                    "unknown field, use account / realm",
                ));
            }
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(Self { account, realm })
    }
}

pub(crate) fn sa_check_http_basic_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let basic = if attr.is_empty() {
        BasicAttr {
            account: String::new(),
            realm: "sa-token".to_string(),
        }
    } else {
        parse_macro_input!(attr as BasicAttr)
    };
    let account = basic.account;
    let realm = basic.realm;
    let input = parse_macro_input!(item as ItemFn);
    expand_checked_fn(
        &input,
        quote! {
            sa_token_core::http_basic::check(#realm, #account)?;
        },
    )
}
