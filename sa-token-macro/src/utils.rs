// Author: 金书记 | Author: Jin Shuji
//
//! Shared helpers for sa-token procedural macros.
//! sa-token 过程宏的共享工具。

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Attribute, ItemFn, LitStr, ReturnType, Token, parse::Parser, punctuated::Punctuated};

/// Compile-error if the function is not `async fn`.
/// 目标函数不是 `async fn` 时生成编译错误。
pub(crate) fn ensure_async_fn(input: &ItemFn) -> Option<TokenStream> {
    if input.sig.asyncness.is_none() {
        let msg = format!(
            "sa_check_* requires `{}` to be async (`async fn`)",
            input.sig.ident
        );
        return Some(
            syn::Error::new_spanned(&input.sig.ident, msg)
                .to_compile_error()
                .into(),
        );
    }
    None
}

/// Compile-error if the function has no return type (`?` needs `Result`).
/// 无返回类型时生成编译错误（`?` 需要 `Result`）。
pub(crate) fn ensure_result_fn(input: &ItemFn) -> Option<TokenStream> {
    if matches!(input.sig.output, ReturnType::Default) {
        let msg = format!(
            "sa_check_* requires `{}` to return `Result<T, E>` where `E: From<sa_token_core::SaTokenError>`",
            input.sig.ident
        );
        return Some(
            syn::Error::new_spanned(&input.sig.ident, msg)
                .to_compile_error()
                .into(),
        );
    }
    None
}

/// True when attrs contain `#[sa_ignore]`.
/// 属性列表是否含 `#[sa_ignore]`。
pub(crate) fn has_sa_ignore(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("sa_ignore"))
}

/// True when attrs contain any `#[sa_check_*]`.
/// 属性列表是否含任意 `#[sa_check_*]`。
pub(crate) fn has_sa_check(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path()
            .get_ident()
            .is_some_and(|id| id.to_string().starts_with("sa_check_"))
    })
}

/// `#[sa_ignore]` must not stack with `#[sa_check_*]`.
/// `#[sa_ignore]` 不得与 `#[sa_check_*]` 叠用。
pub(crate) fn reject_ignore_conflict(input: &ItemFn) -> Option<TokenStream> {
    if has_sa_ignore(&input.attrs) && has_sa_check(&input.attrs) {
        return Some(
            syn::Error::new_spanned(
                &input.sig.ident,
                "cannot combine #[sa_ignore] with #[sa_check_*]; pick one",
            )
            .to_compile_error()
            .into(),
        );
    }
    None
}

/// Insert `check_code` at the start of an async `Result`-returning function.
/// 在 async + Result 函数体开头插入 `check_code`。
///
/// Preserves vis / generics / where-clause / original attrs.
/// 保留可见性、泛型、where 子句与原属性。
///
/// Does **not** add `#[doc(hidden)]` (handlers must stay in rustdoc).
/// **不**添加 `#[doc(hidden)]`（业务 handler 必须出现在 rustdoc 中）。
pub(crate) fn expand_checked_fn(input: &ItemFn, check_code: TokenStream2) -> TokenStream {
    if let Some(err) = ensure_async_fn(input) {
        return err;
    }
    if let Some(err) = ensure_result_fn(input) {
        return err;
    }
    if let Some(err) = reject_ignore_conflict(input) {
        return err;
    }

    let fn_name = &input.sig.ident;
    let fn_inputs = &input.sig.inputs;
    let fn_output = &input.sig.output;
    let fn_body = &input.block;
    let fn_attrs = &input.attrs;
    let fn_vis = &input.vis;
    let fn_asyncness = &input.sig.asyncness;
    let fn_generics = &input.sig.generics;
    let fn_where_clause = &input.sig.generics.where_clause;

    quote! {
        #(#fn_attrs)*
        #fn_vis #fn_asyncness fn #fn_name #fn_generics(#fn_inputs) #fn_output #fn_where_clause {
            #check_code
            #fn_body
        }
    }
    .into()
}

/// Parse a comma-separated `"a", "b"` list; empty or syntax error → compile_error.
/// 解析逗号分隔的字符串列表；为空或语法错误时 compile_error。
pub(crate) fn parse_nonempty_str_list(
    attr: TokenStream,
    empty_msg: &str,
) -> Result<Vec<LitStr>, TokenStream> {
    let parser = Punctuated::<LitStr, Token![,]>::parse_terminated;
    match parser.parse(attr) {
        Ok(list) => {
            let lits: Vec<LitStr> = list.into_iter().collect();
            if lits.is_empty() {
                Err(syn::Error::new(proc_macro2::Span::call_site(), empty_msg)
                    .to_compile_error()
                    .into())
            } else {
                Ok(lits)
            }
        }
        Err(e) => Err(e.to_compile_error().into()),
    }
}

/// Tokens: resolve current login_id from context + storage.
/// 生成：从上下文+存储解析当前 login_id。
pub(crate) fn resolve_login_id_tokens() -> TokenStream2 {
    quote! {
        let __sa_login_id = sa_token_core::StpUtil::get_login_id_as_string().await?;
    }
}

/// Tokens: async login check (C2 strong path).
/// 生成：异步登录强校验（C2 路径）。
pub(crate) fn check_login_async_tokens() -> TokenStream2 {
    quote! {
        sa_token_core::StpUtil::check_login_current_async().await?;
    }
}
