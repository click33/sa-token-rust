// Author: 金书记 | Author: Jin Shuji
//
//! Permission check macro (optional role fallback via `or_role`).
//! 权限检查宏（可通过 `or_role` 做角色兜底）。

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Ident, ItemFn, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

use crate::utils::{expand_checked_fn, resolve_login_id_tokens};

enum PermAttr {
    Simple(LitStr),
    Named {
        value: LitStr,
        or_role: Option<LitStr>,
    },
}

impl Parse for PermAttr {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.peek(LitStr) {
            let lit: LitStr = input.parse()?;
            if !input.is_empty() {
                return Err(input.error("unexpected tokens after permission string"));
            }
            return Ok(PermAttr::Simple(lit));
        }
        let mut value: Option<LitStr> = None;
        let mut or_role: Option<LitStr> = None;
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let lit: LitStr = input.parse()?;
            if key == "value" {
                value = Some(lit);
            } else if key == "or_role" {
                or_role = Some(lit);
            } else {
                return Err(syn::Error::new_spanned(
                    key,
                    "unknown field, use value / or_role",
                ));
            }
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }
        let value = value.ok_or_else(|| input.error("missing value = \"permission\""))?;
        Ok(PermAttr::Named { value, or_role })
    }
}

pub(crate) fn sa_check_permission_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let perm_attr = parse_macro_input!(attr as PermAttr);
    let input = parse_macro_input!(item as ItemFn);

    let (perm_value, or_role) = match &perm_attr {
        PermAttr::Simple(l) => (l.value(), None),
        PermAttr::Named { value, or_role } => (value.value(), or_role.as_ref().map(|l| l.value())),
    };
    if perm_value.trim().is_empty() {
        return syn::Error::new_spanned(&input.sig.ident, "Permission identifier cannot be empty")
            .to_compile_error()
            .into();
    }

    let login_id = resolve_login_id_tokens();
    let check_code = if let Some(role) = or_role {
        quote! {
            #login_id
            let __sa_perm_ok = sa_token_core::StpUtil::check_permission(&__sa_login_id, #perm_value)
                .await
                .is_ok();
            if !__sa_perm_ok {
                sa_token_core::StpUtil::check_role(&__sa_login_id, #role).await?;
            }
        }
    } else {
        quote! {
            #login_id
            sa_token_core::StpUtil::check_permission(&__sa_login_id, #perm_value).await?;
        }
    };

    expand_checked_fn(&input, check_code)
}
