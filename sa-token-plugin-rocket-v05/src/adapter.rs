// Author: 金书记
//
//! Rocket request/response adapters for `SaRequest` / `SaResponse`.
//! Rocket 请求／响应适配器，实现 `SaRequest` / `SaResponse`。

use rocket::http::{ContentType, Cookie, Header, Status};
use rocket::{Request, Response};
use sa_token_adapter::context::{CookieOptions, SaRequest, SaResponse};
use serde::Serialize;
use std::collections::HashMap;

/// Borrows Rocket [`Request`] for synchronous `SaRequest` use (caller must not hold across `.await` with incompatible lifetimes).
/// 借用 Rocket [`Request`] 实现同步 `SaRequest`（注意不要在不兼容的生命周期下跨 `.await` 持有）。
pub struct RocketRequestAdapter<'a> {
    request: &'a Request<'a>,
}

impl<'a> RocketRequestAdapter<'a> {
    pub fn new(request: &'a Request<'a>) -> Self {
        Self { request }
    }
}

impl<'a> SaRequest for RocketRequestAdapter<'a> {
    fn get_header(&self, name: &str) -> Option<String> {
        self.request.headers().get_one(name).map(|s| s.to_string())
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        self.request
            .cookies()
            .get(name)
            .map(|c| c.value().to_string())
    }

    fn get_param(&self, name: &str) -> Option<String> {
        // Rocket 的查询参数需要从 URI 中提取
        if let Some(query) = self.request.uri().query() {
            return parse_query_string(query.as_str()).get(name).cloned();
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
        self.request.client_ip().map(|ip| ip.to_string())
    }
}

/// Owned snapshot of headers/cookies/query/path required by **`run_auth_flow`** in `rocket-core`.
/// 承载 **`run_auth_flow`**（`rocket-core`）所需的请求头/Cookie/查询串/路径等字段副本。
///
/// English: do not hold a borrow of [`Request`] across `.await` in Fairings — build this struct first.
/// 中文：Fairing 内勿让对 [`Request`] 的借用跨过 `.await`，须先构造本结构体。
pub struct RocketCapturedRequest {
    token_name: String,
    token_name_header: Option<String>,
    authorization: Option<String>,
    cookie_token: Option<String>,
    query_token: Option<String>,
    path: String,
    method: String,
    client_ip: Option<String>,
}

impl RocketCapturedRequest {
    /// Build snapshot from live request (sync only). | 从当前请求构建快照（仅同步调用）。
    pub fn capture(req: &Request<'_>, token_name: &str) -> Self {
        let path = req.uri().path().to_string();
        let method = req.method().to_string();
        let client_ip = req.client_ip().map(|ip| ip.to_string());
        let token_name_header = req.headers().get_one(token_name).map(|s| s.to_string());
        let authorization = if !token_name.eq_ignore_ascii_case("authorization") {
            req.headers()
                .get_one("Authorization")
                .map(|s| s.to_string())
        } else {
            None
        };
        let cookie_token = req.cookies().get(token_name).map(|c| c.value().to_string());
        let query_token = req
            .uri()
            .query()
            .and_then(|q| parse_query_string(q.as_str()).get(token_name).cloned());
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

impl SaRequest for RocketCapturedRequest {
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

/// Rocket 响应适配器
pub struct RocketResponseAdapter<'a> {
    response: &'a mut Response<'a>,
}

impl<'a> RocketResponseAdapter<'a> {
    pub fn new(response: &'a mut Response<'a>) -> Self {
        Self { response }
    }
}

impl<'a> SaResponse for RocketResponseAdapter<'a> {
    fn set_header(&mut self, name: &str, value: &str) {
        self.response
            .set_header(Header::new(name.to_string(), value.to_string()));
    }

    fn set_cookie(&mut self, name: &str, value: &str, options: CookieOptions) {
        let mut cookie = Cookie::new(name.to_string(), value.to_string());

        if let Some(domain) = options.domain {
            cookie.set_domain(domain);
        }
        if let Some(path) = options.path {
            cookie.set_path(path);
        }
        if let Some(max_age) = options.max_age {
            cookie.set_max_age(rocket::time::Duration::seconds(max_age));
        }
        cookie.set_http_only(options.http_only);
        cookie.set_secure(options.secure);

        if let Some(same_site) = options.same_site {
            use rocket::http::SameSite;
            use sa_token_adapter::context::SameSite as SaSameSite;

            let ss = match same_site {
                SaSameSite::Strict => SameSite::Strict,
                SaSameSite::Lax => SameSite::Lax,
                SaSameSite::None => SameSite::None,
            };
            cookie.set_same_site(ss);
        }

        self.response.adjoin_header(cookie);
    }

    fn set_status(&mut self, status: u16) {
        if let Some(status_code) = Status::from_code(status) {
            self.response.set_status(status_code);
        }
    }

    fn set_json_body<T: Serialize>(&mut self, body: T) -> Result<(), serde_json::Error> {
        let json = serde_json::to_string(&body)?;
        self.response.set_header(ContentType::JSON);
        self.response
            .set_sized_body(Some(json.len()), std::io::Cursor::new(json));
        Ok(())
    }
}

/// 解析查询字符串
fn parse_query_string(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=')
            && let Ok(decoded_value) = urlencoding::decode(value)
        {
            params.insert(key.to_string(), decoded_value.to_string());
        }
    }
    params
}
