use gotham::hyper::{HeaderMap, Uri};
use sa_token_adapter::context::{CookieOptions, SaRequest, SaResponse};
use serde::Serialize;

/// 中文: Gotham 请求适配器，实现 SaRequest 接口
/// English: Gotham request adapter implementing SaRequest trait
pub struct GothamRequestAdapter<'a> {
    headers: &'a HeaderMap,
    uri: &'a Uri,
}

impl<'a> GothamRequestAdapter<'a> {
    /// 中文: 通过 HeaderMap 和 Uri 构造适配器
    /// English: Constructs adapter from HeaderMap and Uri
    pub fn new(headers: &'a HeaderMap, uri: &'a Uri) -> Self {
        Self { headers, uri }
    }
}

impl<'a> SaRequest for GothamRequestAdapter<'a> {
    /// 中文: 读取指定 Header
    /// English: Retrieves specified header
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// 中文: 解析原始 Cookie 字符串
    /// English: Parses raw cookie string
    fn get_cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|cookies| {
                cookies.split(';').find_map(|cookie| {
                    let mut parts = cookie.trim().splitn(2, '=');
                    match (parts.next(), parts.next()) {
                        (Some(k), Some(v)) if k == name => Some(v.to_string()),
                        _ => None,
                    }
                })
            })
    }

    /// 中文: 查找查询参数
    /// English: Looks up query parameter
    fn get_param(&self, name: &str) -> Option<String> {
        self.uri.query().and_then(|query| {
            query.split('&').find_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                match (parts.next(), parts.next()) {
                    (Some(k), Some(v)) if k == name => {
                        urlencoding::decode(v).ok().map(|s| s.to_string())
                    }
                    _ => None,
                }
            })
        })
    }

    /// 中文: 返回路径
    /// English: Returns path
    fn get_path(&self) -> String {
        self.uri.path().to_string()
    }

    /// 中文: Gotham 在此阶段无法直接获得 Method
    /// English: Method not directly available in this context
    fn get_method(&self) -> String {
        "GET".to_string()
    }

    /// 中文: Gotham 状态中默认无法获取客户端 IP
    /// English: Client IP not available by default in Gotham state
    fn get_client_ip(&self) -> Option<String> {
        None
    }
}

use gotham::state::State;

/// Header + URI fields copied out of Gotham [`State`] so `run_auth_flow` can `.await` safely.
/// 从 Gotham [`State`] 拷贝 Header 与 URI 字段，使 `run_auth_flow` 可安全 `.await`。
pub struct GothamCapturedRequest {
    token_name: String,
    token_name_header: Option<String>,
    authorization: Option<String>,
    cookie_token: Option<String>,
    query_token: Option<String>,
    path: String,
    method: String,
}

impl GothamCapturedRequest {
    /// Best-effort read: missing `HeaderMap`/`Uri` yields empty optional fields.
    /// 尽力读取：缺少 `HeaderMap`/`Uri` 时对应字段为空。
    pub fn capture(state: &State, token_name: &str) -> Self {
        use gotham::hyper::{HeaderMap, Uri};

        let token_name_header = state.try_borrow::<HeaderMap>().and_then(|headers| {
            headers
                .get(token_name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        });
        let authorization = if !token_name.eq_ignore_ascii_case("authorization") {
            state.try_borrow::<HeaderMap>().and_then(|headers| {
                headers
                    .get("authorization")
                    .or_else(|| headers.get("Authorization"))
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
        } else {
            None
        };
        let cookie_token = state.try_borrow::<HeaderMap>().and_then(|headers| {
            headers
                .get("cookie")
                .and_then(|h| h.to_str().ok())
                .and_then(|cookie_str| {
                    cookie_str.split(';').find_map(|cookie| {
                        let mut parts = cookie.trim().splitn(2, '=');
                        match (parts.next(), parts.next()) {
                            (Some(k), Some(v)) if k == token_name => Some(v.to_string()),
                            _ => None,
                        }
                    })
                })
        });
        let (path, query_token) = if let Some(uri) = state.try_borrow::<Uri>() {
            let path = uri.path().to_string();
            let q = uri.query().and_then(|query| {
                query.split('&').find_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    match (parts.next(), parts.next()) {
                        (Some(k), Some(v)) if k == token_name => {
                            urlencoding::decode(v).ok().map(|s| s.to_string())
                        }
                        _ => None,
                    }
                })
            });
            (path, q)
        } else {
            (String::new(), None)
        };

        Self {
            token_name: token_name.to_string(),
            token_name_header,
            authorization,
            cookie_token,
            query_token,
            path,
            method: "GET".to_string(),
        }
    }
}

impl SaRequest for GothamCapturedRequest {
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
        None
    }
}

/// 中文: Gotham 响应适配器，实现 SaResponse 接口
/// English: Gotham response adapter implementing SaResponse trait
pub struct GothamResponseAdapter {
    headers: Vec<(String, String)>,
    body: Option<String>,
}

impl GothamResponseAdapter {
    /// 中文: 创建空响应适配器
    /// English: Creates an empty response adapter
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
            body: None,
        }
    }
}

impl Default for GothamResponseAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SaResponse for GothamResponseAdapter {
    /// 中文: 设置返回头
    /// English: Sets response header
    fn set_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// 中文: 追加 Set-Cookie
    /// English: Appends Set-Cookie header
    fn set_cookie(&mut self, name: &str, value: &str, _options: CookieOptions) {
        self.headers
            .push(("Set-Cookie".to_string(), format!("{}={}", name, value)));
    }

    /// 中文: Gotham 响应构建时再处理状态码
    /// English: Status code handled when building Gotham response
    fn set_status(&mut self, _status: u16) {}

    /// 中文: 序列化 JSON 并保存到 body
    /// English: Serializes JSON payload and stores it
    fn set_json_body<T: Serialize>(&mut self, body: T) -> Result<(), serde_json::Error> {
        let json = serde_json::to_string(&body)?;
        self.body = Some(json);
        self.headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        Ok(())
    }
}
