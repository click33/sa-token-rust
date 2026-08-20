// Author: 金书记
//
// 中文 | English
// Salvo 请求/响应适配器 | Salvo request/response adapter

use sa_token_adapter::{CookieOptions, SaRequest, SaResponse, build_cookie_string};
use salvo::prelude::*;
use serde::Serialize;

/// 中文 | English
/// Salvo 请求适配器 | Salvo request adapter
pub struct SalvoRequestAdapter<'a> {
    request: &'a Request,
}

impl<'a> SalvoRequestAdapter<'a> {
    /// 中文 | English
    /// 创建新的请求适配器 | Create a new request adapter
    pub fn new(request: &'a Request) -> Self {
        Self { request }
    }
}

impl<'a> SaRequest for SalvoRequestAdapter<'a> {
    fn get_header(&self, name: &str) -> Option<String> {
        self.request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        // 先尝试使用 cookie 方法 | First try using cookie method
        if let Some(cookie) = self.request.cookie(name) {
            return Some(cookie.value().to_string());
        }

        // 如果没有找到，手动解析 Cookie 头 | If not found, manually parse Cookie header
        if let Some(cookie_header) = self.request.headers().get("cookie")
            && let Ok(cookie_str) = cookie_header.to_str()
        {
            let cookies = sa_token_adapter::utils::parse_cookies(cookie_str);
            if let Some(value) = cookies.get(name) {
                return Some(value.to_string());
            }
        }

        None
    }

    fn get_param(&self, name: &str) -> Option<String> {
        // 先尝试使用 query 方法 | First try using query method
        if let Some(value) = self.request.query::<String>(name) {
            return Some(value);
        }

        // 如果没有找到，手动解析查询字符串 | If not found, manually parse query string
        if let Some(query) = self.request.uri().query() {
            let params = sa_token_adapter::utils::parse_query_string(query);
            if let Some(value) = params.get(name) {
                return Some(value.to_string());
            }
        }

        None
    }

    fn get_path(&self) -> String {
        self.request.uri().path().to_string()
    }

    fn get_method(&self) -> String {
        self.request.method().to_string()
    }

    fn get_client_ip(&self) -> Option<String> {
        Some(self.request.remote_addr().to_string())
    }
}

/// Request-field snapshot before `await` for **`run_auth_flow`** / **`extract_token`**.
/// `.await` 前的请求字段快照，供 **`run_auth_flow`** / **`extract_token`** 使用，避免借用 [`Request`] 跨过异步点。
pub struct SalvoCapturedRequest {
    token_name: String,
    token_name_header: Option<String>,
    authorization: Option<String>,
    cookie_token: Option<String>,
    query_token: Option<String>,
    path: String,
    method: String,
    client_ip: Option<String>,
}

impl SalvoCapturedRequest {
    /// Copy headers/cookies/query synchronously from live Salvo **`Request`**.
    /// 从 Salvo **`Request`** 同步拷贝 Header/Cookie/Query。
    pub fn capture(req: &Request, token_name: &str) -> Self {
        let path = req.uri().path().to_string();
        let method = req.method().to_string();
        let client_ip = Some(req.remote_addr().to_string());
        let token_name_header = req
            .headers()
            .get(token_name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let authorization = if !token_name.eq_ignore_ascii_case("authorization") {
            req.headers()
                .get("authorization")
                .or_else(|| req.headers().get("Authorization"))
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        } else {
            None
        };

        let cookie_token = req
            .cookie(token_name)
            .map(|c| c.value().to_string())
            .or_else(|| {
                req.headers()
                    .get("cookie")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|cookie_str| {
                        let cookies = sa_token_adapter::utils::parse_cookies(cookie_str);
                        cookies.get(token_name).map(|s| (*s).to_string())
                    })
            });

        let query_token = req.query::<String>(token_name).or_else(|| {
            req.uri().query().and_then(|q| {
                let params = sa_token_adapter::utils::parse_query_string(q);
                params.get(token_name).cloned()
            })
        });

        Self {
            token_name: token_name.to_string(),
            token_name_header,
            authorization,
            cookie_token,
            query_token,
            path,
            method,
            client_ip,
        }
    }
}

impl SaRequest for SalvoCapturedRequest {
    fn get_header(&self, name: &str) -> Option<String> {
        if name.eq_ignore_ascii_case(&self.token_name) {
            return self.token_name_header.clone();
        }
        if !self.token_name.eq_ignore_ascii_case("authorization")
            && name.eq_ignore_ascii_case("authorization")
        {
            return self.authorization.clone();
        }
        None
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        if name.eq_ignore_ascii_case(&self.token_name) {
            self.cookie_token.clone()
        } else {
            None
        }
    }

    fn get_param(&self, name: &str) -> Option<String> {
        if name.eq_ignore_ascii_case(&self.token_name) {
            self.query_token.clone()
        } else {
            None
        }
    }

    fn get_path(&self) -> String {
        self.path.clone()
    }

    fn get_method(&self) -> String {
        self.method.clone()
    }

    fn get_client_ip(&self) -> Option<String> {
        self.client_ip.clone()
    }
}

/// 中文 | English
/// Salvo 响应适配器 | Salvo response adapter
pub struct SalvoResponseAdapter<'a> {
    response: &'a mut Response,
}

impl<'a> SalvoResponseAdapter<'a> {
    /// 中文 | English
    /// 创建新的响应适配器 | Create a new response adapter
    pub fn new(response: &'a mut Response) -> Self {
        Self { response }
    }
}

impl<'a> SaResponse for SalvoResponseAdapter<'a> {
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
        let cookie_string = build_cookie_string(name, value, options);
        self.set_header("Set-Cookie", &cookie_string);
    }

    fn set_status(&mut self, status: u16) {
        if let Ok(status_code) = StatusCode::from_u16(status) {
            self.response.status_code(status_code);
        }
    }

    fn set_json_body<U: Serialize>(&mut self, body: U) -> Result<(), serde_json::Error> {
        match serde_json::to_string(&body) {
            Ok(json) => {
                self.response.render(Text::Json(json));
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
