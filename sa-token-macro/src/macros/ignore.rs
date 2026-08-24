// Author: 金书记 | Author: Jin Shuji
//! Skip inserting StpUtil checks on this item.
//! 本 item 不插入 StpUtil 检查。
//!
//! This does **not** skip framework middleware. Use `PathAuthConfig::exclude` for that.
//! **不会**跳过框架中间件。中间件放行请用 `PathAuthConfig::exclude`。

use proc_macro::TokenStream;
use quote::quote;
use syn::{Item, parse_macro_input};

use crate::utils::has_sa_check;

pub(crate) fn sa_ignore_impl(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as Item);
    match input {
        Item::Fn(item_fn) => {
            // Expanding sa_ignore: any remaining sa_check_* on the same item is a conflict.
            // 展开 sa_ignore 时，同一 item 上仍有 sa_check_* 即冲突。
            if has_sa_check(&item_fn.attrs) {
                return syn::Error::new_spanned(
                    &item_fn.sig.ident,
                    "cannot combine #[sa_ignore] with #[sa_check_*]; pick one",
                )
                .to_compile_error()
                .into();
            }
            quote! { #item_fn }.into()
        }
        Item::Struct(s) => quote! { #s }.into(),
        Item::Impl(i) => quote! { #i }.into(),
        other => quote! { #other }.into(),
    }
}
