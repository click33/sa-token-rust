// Author: 金书记
//
//! Axum request/response adapters (`http` 1.x, shared across axum 0.7+).

use http::{Request, Response};
use sa_token_adapter::context::{CookieOptions, SaRequest, SaResponse};
use sa_token_adapter::utils::{parse_cookies, parse_query_string};
use serde::Serialize;

/// 从 `Request` 同步克隆头与 URI、方法，供 `run_auth_flow` 在 `.await` 前使用，避免 Axum
/// `Body` 非 `Sync` 时 `AxumRequestAdapter` 借请求导致 `async` 块非 `Send`。
#[derive(Debug, Clone)]
pub struct AxumRequestSnapshot {
    headers: http::HeaderMap,
    uri: http::Uri,
    method: String,
}

impl AxumRequestSnapshot {
    pub fn capture<T>(request: &Request<T>) -> Self {
        Self {
            headers: request.headers().clone(),
            uri: request.uri().clone(),
            method: request.method().as_str().to_string(),
        }
    }
}

impl SaRequest for AxumRequestSnapshot {
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
            .and_then(|cookies| parse_cookies(cookies).get(name).cloned())
    }

    fn get_param(&self, name: &str) -> Option<String> {
        self.uri
            .query()
            .and_then(|query| parse_query_string(query).get(name).cloned())
    }

    fn get_path(&self) -> String {
        self.uri.path().to_string()
    }

    fn get_method(&self) -> String {
        self.method.clone()
    }
}

/// Wraps `http::Request` for [`SaRequest`].
pub struct AxumRequestAdapter<'a, T> {
    request: &'a Request<T>,
}

impl<'a, T> AxumRequestAdapter<'a, T> {
    pub fn new(request: &'a Request<T>) -> Self {
        Self { request }
    }
}

impl<'a, T> SaRequest for AxumRequestAdapter<'a, T> {
    fn get_header(&self, name: &str) -> Option<String> {
        self.request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        self.request
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|cookies| parse_cookies(cookies).get(name).cloned())
    }

    fn get_param(&self, name: &str) -> Option<String> {
        self.request
            .uri()
            .query()
            .and_then(|query| parse_query_string(query).get(name).cloned())
    }

    fn get_path(&self) -> String {
        self.request.uri().path().to_string()
    }

    fn get_method(&self) -> String {
        self.request.method().to_string()
    }
}

/// Response wrapper for [`SaResponse`].
pub struct AxumResponseAdapter<T> {
    response: Response<T>,
}

impl<T> AxumResponseAdapter<T> {
    pub fn new(response: Response<T>) -> Self {
        Self { response }
    }

    pub fn into_response(self) -> Response<T> {
        self.response
    }
}

impl<T> SaResponse for AxumResponseAdapter<T> {
    fn set_header(&mut self, name: &str, value: &str) {
        if let Ok(header_name) = http::header::HeaderName::from_bytes(name.as_bytes())
            && let Ok(header_value) = http::header::HeaderValue::from_str(value)
        {
            self.response
                .headers_mut()
                .insert(header_name, header_value);
        }
    }

    fn set_cookie(&mut self, name: &str, value: &str, options: CookieOptions) {
        let mut cookie = format!("{}={}", name, value);

        if let Some(domain) = options.domain {
            cookie.push_str(&format!("; Domain={}", domain));
        }
        if let Some(path) = options.path {
            cookie.push_str(&format!("; Path={}", path));
        }
        if let Some(max_age) = options.max_age {
            cookie.push_str(&format!("; Max-Age={}", max_age));
        }
        if options.http_only {
            cookie.push_str("; HttpOnly");
        }
        if options.secure {
            cookie.push_str("; Secure");
        }

        self.set_header("Set-Cookie", &cookie);
    }

    fn set_status(&mut self, status: u16) {
        *self.response.status_mut() =
            http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::OK);
    }

    fn set_json_body<U: Serialize>(&mut self, _body: U) -> Result<(), serde_json::Error> {
        Ok(())
    }
}
