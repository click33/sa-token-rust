// Author: 金书记
//
//! # sa-token-plugin-common
//!
//! Shared primitives for all sa-token web-framework plugins: application state,
//! JSON rejection helpers, request snapshot trait, and typed extension keys.
//!
//! This crate contains **no** framework-specific types (no `axum::Request`,
//! no `warp::Filter`, etc.).

#![allow(missing_docs, missing_debug_implementations)]

pub mod ext;
pub mod rejection;
pub mod snapshot;
pub mod state;

pub use ext::{SaLoginId, apply_to_typed_extensions};
pub use rejection::{
    CONTENT_TYPE_JSON, SaTokenHttpStatus, WWW_AUTHENTICATE, forbidden_json, forbidden_role_json,
    http_rejection_for, safe_required_json, unauthorized_basic_json, unauthorized_json,
    write_json_body, www_authenticate_basic,
};
pub use snapshot::CapturedRequest;
pub use state::{SaTokenState, SaTokenStateBuilder};

pub use sa_token_adapter::{self, storage::SaStorage};
pub use sa_token_core::{self, prelude::*};
