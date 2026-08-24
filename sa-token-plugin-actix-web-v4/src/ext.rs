//! Actix-specific helpers (`web::Data`).

use actix_web::web::Data;

use sa_token_plugin_common::SaTokenState;

pub type SaTokenData = Data<SaTokenState>;

#[inline]
pub fn into_data(state: SaTokenState) -> Data<SaTokenState> {
    Data::new(state)
}
