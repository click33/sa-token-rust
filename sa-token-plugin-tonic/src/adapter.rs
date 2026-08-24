// Author: 金书记
//
// 中文 | English
// Tonic gRPC 请求/响应适配器 | Tonic gRPC request/response adapters
//
// 修复 #4: from_metadata 使用 to_str() 而非 format!("{:?}")
// 新增 TonicCapturedRequest 供 run_auth_flow 使用

use http::{HeaderMap, Request as HttpRequest};
use sa_token_adapter::utils::parse_cookies;
use sa_token_adapter::{CookieOptions, SaRequest, SaResponse};
use serde::Serialize;
use std::collections::HashMap;

// ============================================================================
// 中文: gRPC 请求快照（供 run_auth_flow 使用）
// English: gRPC request snapshot (for run_auth_flow)
// ============================================================================

/// 中文: gRPC 请求快照，在 `.await` 前从 HTTP 或 metadata 克隆，避免跨 await 借用
/// English: gRPC request snapshot, cloned from HTTP or metadata before `.await` to avoid cross-await borrows
#[derive(Debug, Clone)]
pub struct TonicCapturedRequest {
    headers: HashMap<String, String>,
    method: String,
    path: String,
}

impl TonicCapturedRequest {
    /// 中文: 从 `http::Request` 捕获（`SaTokenGrpcLayer` Tower 层使用）
    /// English: Capture from `http::Request` (used by `SaTokenGrpcLayer` Tower layer)
    pub fn from_http<T>(req: &HttpRequest<T>) -> Self {
        let mut headers = HashMap::new();
        for (key, value) in req.headers().iter() {
            if let Ok(v) = value.to_str() {
                headers.insert(key.as_str().to_string(), v.to_string());
            }
        }
        Self {
            headers,
            method: req.method().as_str().to_string(),
            path: req.uri().path().to_string(),
        }
    }

    /// 中文: 从 tonic metadata 捕获（`GrpcServerInterceptor` 使用）
    /// English: Capture from tonic metadata (used by `GrpcServerInterceptor`)
    ///
    /// 中文: 修复: 使用 `to_str()` 而非 `format!("{:?}")` 避免 Debug 引号污染
    /// English: Fix: uses `to_str()` instead of `format!("{:?}")` to avoid Debug quote pollution
    /// 中文: 解析 gRPC path（用于 Interceptor，无 HTTP URI 时）
    /// English: Resolve gRPC path (for Interceptor when HTTP URI is unavailable)
    pub fn resolve_grpc_path<T>(request: &tonic::Request<T>) -> String {
        if let Some(p) = request.extensions().get::<crate::error::SaTokenGrpcPath>() {
            return p.0.clone();
        }
        if let Some(m) = request.extensions().get::<tonic::GrpcMethod<'_>>() {
            return format!("/{}/{}", m.service(), m.method());
        }
        String::new()
    }

    pub fn from_metadata(
        metadata: &tonic::metadata::MetadataMap,
        path: String,
        method: impl Into<String>,
    ) -> Self {
        let mut headers = HashMap::new();
        for item in metadata.iter() {
            if let tonic::metadata::KeyAndValueRef::Ascii(key, value) = item {
                if let Ok(s) = value.to_str() {
                    headers.insert(key.as_str().to_string(), s.to_string());
                }
            }
        }
        Self {
            headers,
            method: method.into(),
            path,
        }
    }
}

impl SaRequest for TonicCapturedRequest {
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        self.get_header("cookie")
            .and_then(|cookies| parse_cookies(&cookies).get(name).cloned())
    }

    fn get_param(&self, _name: &str) -> Option<String> {
        None
    }

    fn get_path(&self) -> String {
        self.path.clone()
    }

    fn get_method(&self) -> String {
        self.method.clone()
    }
}

// ============================================================================
// 中文: gRPC 请求适配器（旧接口兼容）
// English: gRPC request adapter (legacy interface compat)
// ============================================================================

/// 中文: gRPC 请求适配器，用于包装 tonic metadata
/// English: gRPC request adapter that wraps tonic metadata
pub struct TonicRequestAdapter {
    headers: HashMap<String, String>,
    method: String,
    path: String,
}

impl TonicRequestAdapter {
    /// 中文: 从 headers、method 和 path 创建请求适配器
    /// English: Create a new request adapter from headers, method and path
    pub fn new(headers: HashMap<String, String>, method: String, path: String) -> Self {
        Self {
            headers,
            method,
            path,
        }
    }

    /// 中文: 从 tonic metadata map 创建请求适配器（委托 TonicCapturedRequest 避免重复逻辑）
    /// English: Create from tonic metadata map (delegates to TonicCapturedRequest to avoid duplication)
    pub fn from_metadata(
        metadata: &tonic::metadata::MetadataMap,
        method: String,
        path: String,
    ) -> Self {
        let cap = TonicCapturedRequest::from_metadata(metadata, path, method);
        Self {
            headers: cap.headers,
            method: cap.method,
            path: cap.path,
        }
    }

    /// 中文: 从 http HeaderMap 创建请求适配器
    /// English: Create from http HeaderMap
    pub fn from_header_map(headers: &HeaderMap, method: String, path: String) -> Self {
        let mut map = HashMap::new();
        for (key, value) in headers.iter() {
            let k = key.to_string();
            let v = value.to_str().unwrap_or("");
            map.insert(k, v.to_string());
        }
        Self {
            headers: map,
            method,
            path,
        }
    }

    /// 中文: 获取所有请求头
    /// English: Get all headers
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// 中文: 根据名称获取请求头
    /// English: Get header by name
    pub fn get(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }
}

impl SaRequest for TonicRequestAdapter {
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        self.get_header("cookie")
            .and_then(|cookies| parse_cookies(&cookies).get(name).cloned())
    }

    fn get_param(&self, _name: &str) -> Option<String> {
        None
    }

    fn get_path(&self) -> String {
        self.path.clone()
    }

    fn get_method(&self) -> String {
        self.method.clone()
    }
}

// ============================================================================
// 中文: gRPC 响应适配器
// English: gRPC response adapter
// ============================================================================

/// 中文: gRPC 响应适配器
/// English: Response wrapper for gRPC responses
pub struct TonicResponseAdapter {
    status: u16,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

impl TonicResponseAdapter {
    /// 中文: 创建新的响应适配器
    /// English: Create a new response adapter
    pub fn new() -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: None,
        }
    }

    /// 中文: 获取响应状态码
    /// English: Get the response status
    pub fn status(&self) -> u16 {
        self.status
    }

    /// 中文: 获取所有响应头
    /// English: Get all headers
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// 中文: 获取响应体
    /// English: Get the response body
    pub fn body(&self) -> Option<&str> {
        self.body.as_deref()
    }
}

impl Default for TonicResponseAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SaResponse for TonicResponseAdapter {
    fn set_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
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
        self.status = status;
    }

    fn set_json_body<U: Serialize>(&mut self, body: U) -> Result<(), serde_json::Error> {
        let json = serde_json::to_string(&body)?;
        self.body = Some(json);
        self.headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        Ok(())
    }
}
