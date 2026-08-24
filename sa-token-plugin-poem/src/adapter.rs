// Author: 金书记
//
//! Poem 请求/响应适配器

use poem_03::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use poem_03::{Body, Request, Response};
use sa_token_adapter::context::{CookieOptions, SaRequest, SaResponse};
use serde::Serialize;
use std::collections::HashMap;

/// Poem 请求适配器
pub struct PoemRequestAdapter<'a> {
    request: &'a Request,
}

impl<'a> PoemRequestAdapter<'a> {
    pub fn new(request: &'a Request) -> Self {
        Self { request }
    }
}

impl<'a> SaRequest for PoemRequestAdapter<'a> {
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

/// Poem 响应构建器适配器
pub struct PoemResponseAdapter {
    status: StatusCode,
    headers: HeaderMap,
    body: Option<String>,
}

impl PoemResponseAdapter {
    pub fn new() -> Self {
        Self {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    /// 构建最终的 Poem Response
    pub fn build(self) -> Response {
        let mut response = if let Some(body) = self.body {
            Response::builder()
                .status(self.status)
                .body(Body::from_string(body))
        } else {
            Response::builder().status(self.status).finish()
        };

        // 添加所有响应头
        for (name, value) in self.headers.iter() {
            response.headers_mut().insert(name.clone(), value.clone());
        }

        response
    }
}

impl Default for PoemResponseAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SaResponse for PoemResponseAdapter {
    fn set_header(&mut self, name: &str, value: &str) {
        if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes())
            && let Ok(header_value) = HeaderValue::from_str(value)
        {
            self.headers.insert(header_name, header_value);
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
        if let Some(same_site) = options.same_site {
            cookie.push_str(&format!("; SameSite={:?}", same_site));
        }

        self.set_header("Set-Cookie", &cookie);
    }

    fn set_status(&mut self, status: u16) {
        self.status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    }

    fn set_json_body<U: Serialize>(&mut self, body: U) -> Result<(), serde_json::Error> {
        let json = serde_json::to_string(&body)?;
        self.body = Some(json);
        self.set_header("Content-Type", "application/json");
        Ok(())
    }
}

/// 解析 Cookie 字符串
fn parse_cookies(cookie_header: &str) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for pair in cookie_header.split(';') {
        let mut parts = pair.trim().splitn(2, '=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            cookies.insert(k.to_string(), v.to_string());
        }
    }
    cookies
}

/// 解析查询字符串
fn parse_query_string(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            params.insert(
                urlencoding::decode(k).unwrap_or_default().to_string(),
                urlencoding::decode(v).unwrap_or_default().to_string(),
            );
        }
    }
    params
}
