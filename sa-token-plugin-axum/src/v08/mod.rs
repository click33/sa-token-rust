// Author: 金书记
//
//! Axum 0.8 bindings (`axum_08` / `tower_08` dependency keys).

pub(crate) mod error_response;
pub(crate) mod extractor;
pub(crate) mod layer;
pub(crate) mod middleware;

pub use error_response::sa_token_error_response;
pub use extractor::{LoginIdExtractor, OptionalSaTokenExtractor, SaTokenExtractor};
pub use layer::{SaTokenLayer, SaTokenMiddleware};
pub use middleware::{
    SaCheckLoginLayer, SaCheckLoginMiddleware, SaCheckPermissionLayer, SaCheckPermissionMiddleware,
};
