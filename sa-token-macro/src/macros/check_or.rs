// Author: 金书记 | Author: Jin Shuji
//! Combined OR auth macro (any one check passing is enough).
//! 组合鉴权 OR 宏（任一子检查通过即可）。

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    ItemFn, LitInt, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

use crate::utils::expand_checked_fn;

struct OrCheck {
    kind: syn::Ident,
    value: LitStr,
    level: Option<LitInt>,
}

struct OrAttr {
    checks: Vec<OrCheck>,
}

impl Parse for OrAttr {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut checks = Vec::new();
        while !input.is_empty() {
            let kind: syn::Ident = input.parse()?;
            if kind == "login" || kind == "same_token" {
                checks.push(OrCheck {
                    kind,
                    value: LitStr::new("", Span::call_site()),
                    level: None,
                });
            } else {
                input.parse::<Token![=]>()?;
                if kind == "disable" {
                    let service: LitStr = input.parse()?;
                    let mut level = None;
                    if input.peek(Token![,]) {
                        let fork = input.fork();
                        fork.parse::<Token![,]>()?;
                        let level_kw: syn::Ident = fork.parse()?;
                        if level_kw == "level" {
                            input.parse::<Token![,]>()?;
                            input.parse::<syn::Ident>()?;
                            input.parse::<Token![=]>()?;
                            level = Some(input.parse()?);
                        }
                    }
                    checks.push(OrCheck {
                        kind,
                        value: service,
                        level,
                    });
                } else {
                    let value: LitStr = input.parse()?;
                    checks.push(OrCheck {
                        kind,
                        value,
                        level: None,
                    });
                }
            }
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }
        if checks.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                "At least one check is required, e.g. permission = \"a\", role = \"admin\"",
            ));
        }
        Ok(OrAttr { checks })
    }
}

pub(crate) fn sa_check_or_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let or_attr = parse_macro_input!(attr as OrAttr);
    let input = parse_macro_input!(item as ItemFn);

    let mut perm_lits: Vec<&LitStr> = Vec::new();
    let mut role_lits: Vec<&LitStr> = Vec::new();
    let mut other_branches: Vec<TokenStream2> = Vec::new();

    for check in &or_attr.checks {
        match check.kind.to_string().as_str() {
            "login" => {
                other_branches.push(quote! {
                    if sa_token_core::StpUtil::check_login_current_async().await.is_ok() {
                        __sa_or_passed = true;
                    }
                });
            }
            "permission" => perm_lits.push(&check.value),
            "role" => role_lits.push(&check.value),
            "safe" => {
                let service = &check.value;
                other_branches.push(quote! {
                    if sa_token_core::StpUtil::check_safe(#service).await.is_ok() {
                        __sa_or_passed = true;
                    }
                });
            }
            "disable" => {
                let service = &check.value;
                let level = check
                    .level
                    .as_ref()
                    .map(|l| quote! { #l })
                    .unwrap_or_else(|| {
                        quote! { sa_token_core::MIN_DISABLE_LEVEL }
                    });
                other_branches.push(quote! {
                    {
                        if let Ok(__login_id) = sa_token_core::StpUtil::get_login_id_as_string().await {
                            if sa_token_core::StpUtil::check_disable_level(&__login_id, #service, #level)
                                .await
                                .is_ok()
                            {
                                __sa_or_passed = true;
                            }
                        }
                    }
                });
            }
            "terminal" => {
                let expected = &check.value;
                other_branches.push(quote! {
                    if sa_token_core::StpUtil::check_current_terminal(#expected).await.is_ok() {
                        __sa_or_passed = true;
                    }
                });
            }
            "basic" => {
                let account = &check.value;
                other_branches.push(quote! {
                    if sa_token_core::http_basic::check_account(#account).is_ok() {
                        __sa_or_passed = true;
                    }
                });
            }
            "same_token" => {
                other_branches.push(quote! {
                    if sa_token_core::same_token::check_current_request().await.is_ok() {
                        __sa_or_passed = true;
                    }
                });
            }
            other => {
                return syn::Error::new_spanned(
                    &check.kind,
                    format!(
                        "Unsupported check kind '{}', use login|permission|role|safe|disable|terminal|basic|same_token",
                        other
                    ),
                )
                .to_compile_error()
                .into();
            }
        }
    }

    let grant_check = if perm_lits.is_empty() && role_lits.is_empty() {
        quote! {}
    } else {
        quote! {
            if !__sa_or_passed {
                let __login_id = sa_token_core::StpUtil::get_login_id_as_string().await?;
                sa_token_core::StpUtil::check_permission_or_role(
                    &__login_id,
                    &[#(#perm_lits),*],
                    &[#(#role_lits),*],
                ).await?;
                __sa_or_passed = true;
            }
        }
    };

    let check_code = quote! {
        let mut __sa_or_passed = false;
        #(#other_branches)*
        #grant_check
        if !__sa_or_passed {
            return Err(sa_token_core::SaTokenError::PermissionDenied.into());
        }
    };

    expand_checked_fn(&input, check_code)
}
