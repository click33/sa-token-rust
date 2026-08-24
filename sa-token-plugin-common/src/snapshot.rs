// Author: 金书记
//
//! Request snapshot trait: clone Send + Sync data from a framework request
//! *before* `.await`, so `run_auth_flow` can use it across async boundaries.

use sa_token_adapter::context::SaRequest;

/// Marker for types that have captured request data from a framework `Request`.
///
/// Each binding crate implements this (e.g. `AxumRequestSnapshot`,
/// `WarpRequestSnapshot`).
pub trait CapturedRequest: SaRequest + Send + Sync {}

/// Blanket impl: anything that is `SaRequest + Send + Sync` qualifies.
impl<T> CapturedRequest for T where T: SaRequest + Send + Sync {}
