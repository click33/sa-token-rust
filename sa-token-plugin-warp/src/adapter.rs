// Author: 金书记
//
// 中文 | English
// Warp 请求/响应适配器 | Warp request/response adapters

use sa_token_adapter::{CookieOptions, SaRequest, SaResponse, build_cookie_string, utils};
use serde::Serialize;
use warp_03::http::{HeaderMap, Response, StatusCode};
use warp_03::hyper::body::Bytes;

/// 中文 | English
/// Warp 请求适配器 | Warp request adapter
pub struct WarpRequestAdapter<'a> {
    headers: &'a HeaderMap,
    query: &'a str,
}

impl<'a> WarpRequestAdapter<'a> {
    /// 中文 | English
    /// 创建新的请求适配器 | Create a new request adapter
    pub fn new(headers: &'a HeaderMap, query: &'a str) -> Self {
        Self { headers, query }
    }
}

impl<'a> SaRequest for WarpRequestAdapter<'a> {
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        // Warp 中 Cookie 通常从 Header 中解析 | In Warp, cookies are usually parsed from headers
        if let Some(cookie_header) = self.headers.get("cookie")
            && let Ok(cookie_str) = cookie_header.to_str()
        {
            let cookies = utils::parse_cookies(cookie_str);
            return cookies.get(name).map(|s| s.to_string());
        }
        None
    }

    fn get_param(&self, name: &str) -> Option<String> {
        if !self.query.is_empty() {
            let params = utils::parse_query_string(self.query);
            return params.get(name).map(|s| s.to_string());
        }
        None
    }

    fn get_path(&self) -> String {
        // Warp 中需要从外部传入 | In Warp, this needs to be passed from outside
        String::new()
    }

    fn get_method(&self) -> String {
        // Warp 中需要从外部传入 | In Warp, this needs to be passed from outside
        String::new()
    }

    fn get_client_ip(&self) -> Option<String> {
        // 从常见的代理头中获取 IP | Get IP from common proxy headers
        self.get_header("x-forwarded-for")
            .or_else(|| self.get_header("x-real-ip"))
    }
}

/// 中文 | English
/// Warp 响应适配器 | Warp response adapter
pub struct WarpResponseAdapter {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

impl WarpResponseAdapter {
    /// 中文 | English
    /// 创建新的响应适配器 | Create a new response adapter
    pub fn new() -> Self {
        Self {
            status: StatusCode::OK,
            headers: Vec::new(),
            body: None,
        }
    }

    /// 中文 | English
    /// 构建 Warp Response | Build Warp Response
    pub fn build(self) -> Response<Bytes> {
        let mut builder = Response::builder().status(self.status);

        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }

        let body = self.body.unwrap_or_default();
        builder.body(Bytes::from(body)).unwrap_or_default()
    }
}

impl Default for WarpResponseAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SaResponse for WarpResponseAdapter {
    fn set_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    fn set_cookie(&mut self, name: &str, value: &str, options: CookieOptions) {
        let cookie_string = build_cookie_string(name, value, options);
        self.set_header("Set-Cookie", &cookie_string);
    }

    fn set_status(&mut self, status: u16) {
        if let Ok(status_code) = StatusCode::from_u16(status) {
            self.status = status_code;
        }
    }

    fn set_json_body<T: Serialize>(&mut self, body: T) -> Result<(), serde_json::Error> {
        let json = serde_json::to_string(&body)?;
        self.body = Some(json);
        self.headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        Ok(())
    }
}
