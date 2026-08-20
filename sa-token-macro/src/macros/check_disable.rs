// Author: 金书记 | Author: Jin Shuji
//! Disable-level check macro | 封禁等级检查宏

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    Expr, ExprLit, ItemFn, Lit, LitInt, LitStr, MetaNameValue, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

use crate::utils::expand_checked_fn;

struct DisableAttr {
    service: LitStr,
    level: LitInt,
}

impl Default for DisableAttr {
    fn default() -> Self {
        Self {
            service: LitStr::new("login", Span::call_site()),
            level: LitInt::new("1", Span::call_site()),
        }
    }
}

impl Parse for DisableAttr {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(DisableAttr::default());
        }
        let mut attr = DisableAttr::default();
        if input.peek(LitStr) {
            attr.service = input.parse()?;
        }
        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            let nv: MetaNameValue = input.parse()?;
            if nv.path.is_ident("level") {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Int(i), ..
                }) = nv.value
                {
                    attr.level = i;
                }
            }
        }
        Ok(attr)
    }
}

pub(crate) fn sa_check_disable_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let disable_attr = parse_macro_input!(attr as DisableAttr);
    let input = parse_macro_input!(item as ItemFn);
    let service = &disable_attr.service;
    let level = &disable_attr.level;
    expand_checked_fn(
        &input,
        quote! {
            let __login_id = sa_token_core::StpUtil::get_login_id_as_string().await?;
            sa_token_core::StpUtil::check_disable_level(&__login_id, #service, #level).await?;
        },
    )
}
