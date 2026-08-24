// Author: 金书记
//
// 中文 | English
// Tide 请求/响应适配器 | Tide request/response adapter

use sa_token_adapter::{CookieOptions, SaRequest, SaResponse, build_cookie_string};
use serde::Serialize;
use tide_017::{Request, Response, StatusCode};

/// 中文 | English
/// Tide 请求适配器 | Tide request adapter
pub struct TideRequestAdapter<'a, State> {
    request: &'a Request<State>,
}

impl<'a, State> TideRequestAdapter<'a, State> {
    /// 中文 | English
    /// 创建新的请求适配器 | Create a new request adapter
    pub fn new(request: &'a Request<State>) -> Self {
        Self { request }
    }
}

impl<'a, State> SaRequest for TideRequestAdapter<'a, State> {
    fn get_header(&self, name: &str) -> Option<String> {
        self.request
            .header(name)
            .and_then(|v| v.as_str().parse().ok())
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        // 先尝试使用 cookie 方法 | First try using cookie method
        if let Some(cookie) = self.request.cookie(name) {
            return Some(cookie.value().to_string());
        }

        // 如果没有找到，手动解析 Cookie 头 | If not found, manually parse Cookie header
        if let Some(cookie_header) = self.request.header("cookie")
            && let Some(cookie_str) = cookie_header.get(0)
        {
            let cookies = sa_token_adapter::utils::parse_cookies(cookie_str.as_str());
            if let Some(value) = cookies.get(name) {
                return Some(value.to_string());
            }
        }

        None
    }

    fn get_param(&self, name: &str) -> Option<String> {
        // 先尝试使用 query_pairs 方法 | First try using query_pairs method
        if let Some((_, value)) = self.request.url().query_pairs().find(|(k, _)| k == name) {
            return Some(value.to_string());
        }

        // 如果没有找到，手动解析查询字符串 | If not found, manually parse query string
        if let Some(query) = self.request.url().query() {
            let params = sa_token_adapter::utils::parse_query_string(query);
            if let Some(value) = params.get(name) {
                return Some(value.to_string());
            }
        }

        None
    }

    fn get_path(&self) -> String {
        self.request.url().path().to_string()
    }

    fn get_method(&self) -> String {
        self.request.method().to_string()
    }
}

/// 中文 | English
/// Tide 响应适配器 | Tide response adapter
pub struct TideResponseAdapter {
    response: Response,
}

impl TideResponseAdapter {
    /// 中文 | English
    /// 创建新的响应适配器 | Create a new response adapter
    pub fn new(response: Response) -> Self {
        Self { response }
    }

    /// 中文 | English
    /// 获取内部响应对象 | Get inner response object
    pub fn into_response(self) -> Response {
        self.response
    }
}

impl SaResponse for TideResponseAdapter {
    fn set_header(&mut self, name: &str, value: &str) {
        self.response.insert_header(name, value);
    }

    fn set_cookie(&mut self, name: &str, value: &str, options: CookieOptions) {
        let cookie_string = build_cookie_string(name, value, options);
        self.set_header("Set-Cookie", &cookie_string);
    }

    fn set_status(&mut self, status: u16) {
        // Tide 使用自己的 StatusCode 类型
        let status_code = StatusCode::try_from(status).unwrap_or(StatusCode::Ok);
        self.response.set_status(status_code);
    }

    fn set_json_body<U: Serialize>(&mut self, body: U) -> Result<(), serde_json::Error> {
        match serde_json::to_string(&body) {
            Ok(json) => {
                self.response.set_body(json);
                self.response.set_content_type("application/json");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
