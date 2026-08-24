// Author: 金书记
//
//! Actix-web请求/响应适配器

use actix_web::{HttpRequest, HttpResponse};
use sa_token_adapter::context::{CookieOptions, SaRequest, SaResponse};
use serde::Serialize;
use std::collections::HashMap;

/// Actix-web请求适配器
pub struct ActixRequestAdapter<'a> {
    request: &'a HttpRequest,
}

impl<'a> ActixRequestAdapter<'a> {
    pub fn new(request: &'a HttpRequest) -> Self {
        Self { request }
    }
}

impl<'a> SaRequest for ActixRequestAdapter<'a> {
    fn get_header(&self, name: &str) -> Option<String> {
        self.request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        self.request.cookie(name).map(|c| c.value().to_string())
    }

    fn get_param(&self, name: &str) -> Option<String> {
        // Actix-web 中 match_info 用于路径参数
        // 对于查询参数，需要手动解析
        self.request
            .match_info()
            .get(name)
            .map(|s| s.to_string())
            .or_else(|| {
                // 解析查询字符串
                parse_query_string(self.request.query_string())
                    .get(name)
                    .cloned()
            })
    }

    fn get_path(&self) -> String {
        self.request.path().to_string()
    }

    fn get_method(&self) -> String {
        self.request.method().to_string()
    }

    fn get_client_ip(&self) -> Option<String> {
        self.request.peer_addr().map(|addr| addr.ip().to_string())
    }
}

/// Actix-web响应适配器
pub struct ActixResponseAdapter {
    status: actix_web::http::StatusCode,
    headers: Vec<(String, String)>,
    cookies: Vec<actix_web::cookie::Cookie<'static>>,
    body: Option<String>,
}

impl ActixResponseAdapter {
    pub fn new() -> Self {
        Self {
            status: actix_web::http::StatusCode::OK,
            headers: Vec::new(),
            cookies: Vec::new(),
            body: None,
        }
    }

    /// 构建 HttpResponse
    pub fn build(self) -> HttpResponse {
        let mut builder = HttpResponse::build(self.status);

        for (name, value) in self.headers {
            builder.insert_header((name, value));
        }

        for cookie in self.cookies {
            builder.cookie(cookie);
        }

        if let Some(body) = self.body {
            builder.body(body)
        } else {
            builder.finish()
        }
    }
}

impl Default for ActixResponseAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SaResponse for ActixResponseAdapter {
    fn set_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    fn set_cookie(&mut self, name: &str, value: &str, options: CookieOptions) {
        use actix_web::cookie::{Cookie, SameSite};

        let mut cookie = Cookie::new(name.to_string(), value.to_string());

        if let Some(domain) = options.domain {
            cookie.set_domain(domain);
        }
        if let Some(path) = options.path {
            cookie.set_path(path);
        }
        if let Some(max_age) = options.max_age {
            cookie.set_max_age(actix_web::cookie::time::Duration::seconds(max_age));
        }
        cookie.set_http_only(options.http_only);
        cookie.set_secure(options.secure);

        if let Some(same_site) = options.same_site {
            use sa_token_adapter::context::SameSite as SaSameSite;
            let ss = match same_site {
                SaSameSite::Strict => SameSite::Strict,
                SaSameSite::Lax => SameSite::Lax,
                SaSameSite::None => SameSite::None,
            };
            cookie.set_same_site(ss);
        }

        self.cookies.push(cookie);
    }

    fn set_status(&mut self, status: u16) {
        if let Ok(status_code) = actix_web::http::StatusCode::from_u16(status) {
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
