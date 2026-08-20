// Author: 金书记
//
//! Warp request snapshot: clone headers + query before `.await`, implementing `SaRequest`.

use sa_token_adapter::context::SaRequest;
use sa_token_adapter::utils::parse_cookies;
use warp_03::http::HeaderMap;

/// Warp-specific snapshot (Send + Sync, can be held across async boundaries).
#[derive(Debug, Clone)]
pub struct WarpRequestSnapshot {
    headers: HeaderMap,
    query: std::collections::HashMap<String, String>,
    path: String,
    method: String,
}

impl WarpRequestSnapshot {
    /// Capture headers and query params. Call `with_path` / `with_method` to complete.
    pub fn capture(headers: HeaderMap, query: std::collections::HashMap<String, String>) -> Self {
        Self {
            path: String::new(),
            method: "GET".to_string(),
            headers,
            query,
        }
    }

    /// Set the request path.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Set the HTTP method.
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }
}

impl SaRequest for WarpRequestSnapshot {
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|raw| parse_cookies(raw).get(name).cloned())
    }

    fn get_param(&self, name: &str) -> Option<String> {
        self.query.get(name).cloned()
    }

    fn get_path(&self) -> String {
        self.path.clone()
    }

    fn get_method(&self) -> String {
        self.method.clone()
    }
}
