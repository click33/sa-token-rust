use ntex::web::HttpRequest;
use sa_token_core::token::TokenValue;
use sa_token_plugin_common::SaLoginId;

/// Required token extractor — `None` when middleware did not inject a token.
#[derive(Clone)]
pub struct SaTokenExtractor(pub Option<TokenValue>);

impl SaTokenExtractor {
    /// Read `TokenValue` written by middleware into request extensions.
    pub fn from_request(req: &HttpRequest) -> Self {
        let token = req.extensions().get::<TokenValue>().cloned();
        SaTokenExtractor(token)
    }
}

/// Optional token extractor for routes that do not require login.
#[derive(Clone)]
pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl OptionalSaTokenExtractor {
    /// Read optional `TokenValue` from extensions.
    pub fn from_request(req: &HttpRequest) -> Self {
        let token = req.extensions().get::<TokenValue>().cloned();
        OptionalSaTokenExtractor(token)
    }
}

/// Login ID extractor — `None` when middleware did not inject `SaLoginId`.
#[derive(Clone)]
pub struct LoginIdExtractor(pub Option<String>);

impl LoginIdExtractor {
    /// Read `SaLoginId` from extensions.
    pub fn from_request(req: &HttpRequest) -> Self {
        let id = req.extensions().get::<SaLoginId>().map(|id| id.0.clone());
        LoginIdExtractor(id)
    }
}
