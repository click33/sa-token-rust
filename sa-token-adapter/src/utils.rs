// Author: 金书记
//
// 中文 | English
// 通用工具函数模块 | Common utility functions module
//
// 代码流程逻辑 | Code Flow Logic
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 本模块提供了框架适配器的通用工具函数，简化了新框架集成的复杂度。
// This module provides common utility functions for framework adapters,
// simplifying the complexity of integrating new frameworks.
//
// 核心功能 | Core Features:
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 1. Cookie 解析
//    - parse_cookies(): 解析 HTTP Cookie 头
//    - 支持多个 cookie 对，自动处理空格
//
// 2. 查询字符串解析
//    - parse_query_string(): 解析 URL 查询参数
//    - 自动 URL 解码，支持特殊字符
//
// 3. Cookie 构建
//    - build_cookie_string(): 从 CookieOptions 构建完整的 Set-Cookie 字符串
//    - 支持所有标准 cookie 属性（Domain、Path、Max-Age、Secure、HttpOnly、SameSite）
//
// 4. Header 解析
//    - strip_bearer_prefix() / extract_bearer_or_value(): Bearer 头解析
//
// 使用场景 | Use Cases:
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 新框架适配器实现时，只需调用这些工具函数，无需重复编写解析逻辑：
// When implementing a new framework adapter, just call these utility functions
// without rewriting parsing logic:
//
// ```rust
// impl SaRequest for MyFrameworkRequest {
//     fn get_cookie(&self, name: &str) -> Option<String> {
//         self.get_header("cookie")
//             .and_then(|cookies| parse_cookies(&cookies).get(name).cloned())
//     }
// }
// ```
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use crate::context::CookieOptions;
use std::collections::HashMap;

/// 中文 | English
/// 解析 Cookie 字符串为键值对映射 | Parse Cookie string into key-value map
///
/// # 参数 | Parameters
/// - `cookie_header`: Cookie 头字符串，格式如 "key1=value1; key2=value2"
///
/// # 返回 | Returns
/// - `HashMap<String, String>`: Cookie 名称到值的映射
///
/// # 示例 | Example
/// ```
/// use sa_token_adapter::utils::parse_cookies;
///
/// let cookies = parse_cookies("session=abc123; user=john");
/// assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
/// ```
pub fn parse_cookies(cookie_header: &str) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for pair in cookie_header.split(';') {
        let mut parts = pair.trim().splitn(2, '=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            cookies.insert(k.to_string(), v.to_string());
        }
    }
    cookies
}

/// 中文 | English
/// 解析 URL 查询字符串为键值对映射 | Parse URL query string into key-value map
///
/// # 参数 | Parameters
/// - `query`: 查询字符串，格式如 "key1=value1&key2=value2"
///
/// # 返回 | Returns
/// - `HashMap<String, String>`: 参数名称到值的映射（自动 URL 解码）
///
/// # 示例 | Example
/// ```
/// use sa_token_adapter::utils::parse_query_string;
///
/// let params = parse_query_string("name=John%20Doe&age=30");
/// assert_eq!(params.get("name"), Some(&"John Doe".to_string()));
/// ```
pub fn parse_query_string(query: &str) -> HashMap<String, String> {
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

/// 中文 | English
/// 从 CookieOptions 构建完整的 Set-Cookie 字符串 | Build complete Set-Cookie string from CookieOptions
///
/// # 参数 | Parameters
/// - `name`: Cookie 名称 | Cookie name
/// - `value`: Cookie 值 | Cookie value
/// - `options`: Cookie 选项（Domain、Path、Max-Age 等）| Cookie options
///
/// # 返回 | Returns
/// - `String`: 完整的 Set-Cookie 头值
///
/// # 示例 | Example
/// ```
/// use sa_token_adapter::{utils::build_cookie_string, CookieOptions, SameSite};
///
/// let cookie = build_cookie_string("session", "abc123", CookieOptions {
///     domain: Some("example.com".to_string()),
///     path: Some("/".to_string()),
///     max_age: Some(3600),
///     http_only: true,
///     secure: true,
///     same_site: Some(SameSite::Strict),
/// });
/// // 结果: "session=abc123; Domain=example.com; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict"
/// ```
pub fn build_cookie_string(name: &str, value: &str, options: CookieOptions) -> String {
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
        cookie.push_str(&format!("; SameSite={}", same_site));
    }

    cookie
}

/// Strip a leading **`Bearer `** prefix only; return `None` if the string is not Bearer-shaped.
/// 中文 | English：严格剥离 **`Bearer `** 前缀；非 Bearer 形式返回 **`None`**。
pub fn strip_bearer_prefix(auth_header: &str) -> Option<String> {
    auth_header
        .strip_prefix("Bearer ")
        .map(|token| token.trim().to_string())
}

/// If `Bearer ` present, strip it; otherwise return **`s.trim()`** (same semantics as legacy per-plugin helpers).
/// 若有 `Bearer ` 则剥离；否则返回 **`s.trim()`**（与历史上各 Web 插件本地 helper 语义一致）。
pub fn extract_bearer_or_value(s: &str) -> String {
    strip_bearer_prefix(s).unwrap_or_else(|| s.trim().to_string())
}

/// Alias of [`extract_bearer_or_value`] (alternate name in docs / migration plans).
/// [`extract_bearer_or_value`] 的别名（文档 / 迁移 plan 用词）。
#[inline]
pub fn strip_bearer_or_passthrough(s: &str) -> String {
    extract_bearer_or_value(s)
}

/// 兼容旧 API：语义同 [`strip_bearer_prefix`]。
#[deprecated(
    since = "0.2.0",
    note = "use strip_bearer_prefix or extract_bearer_or_value"
)]
pub fn extract_bearer_token(auth_header: &str) -> Option<String> {
    strip_bearer_prefix(auth_header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookies() {
        let cookies = parse_cookies("session=abc123; user=john; theme=dark");
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
        assert_eq!(cookies.get("user"), Some(&"john".to_string()));
        assert_eq!(cookies.get("theme"), Some(&"dark".to_string()));
    }

    #[test]
    fn test_parse_query_string() {
        let params = parse_query_string("name=John%20Doe&age=30&city=New%20York");
        assert_eq!(params.get("name"), Some(&"John Doe".to_string()));
        assert_eq!(params.get("age"), Some(&"30".to_string()));
        assert_eq!(params.get("city"), Some(&"New York".to_string()));
    }

    #[test]
    fn test_build_cookie_string() {
        use crate::context::SameSite;

        let cookie = build_cookie_string(
            "session",
            "abc123",
            CookieOptions {
                domain: Some("example.com".to_string()),
                path: Some("/".to_string()),
                max_age: Some(3600),
                http_only: true,
                secure: true,
                same_site: Some(SameSite::Strict),
            },
        );

        assert!(cookie.contains("session=abc123"));
        assert!(cookie.contains("Domain=example.com"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=3600"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[test]
    fn test_strip_bearer_prefix() {
        assert_eq!(
            strip_bearer_prefix("Bearer abc123xyz"),
            Some("abc123xyz".to_string())
        );
        assert_eq!(
            strip_bearer_prefix("Bearer  token_with_spaces  "),
            Some("token_with_spaces".to_string())
        );
        assert_eq!(strip_bearer_prefix("Basic xyz"), None);
        assert_eq!(strip_bearer_prefix("Bearer"), None);
    }

    #[test]
    fn test_extract_bearer_or_value() {
        assert_eq!(extract_bearer_or_value("Bearer abc"), "abc");
        assert_eq!(extract_bearer_or_value("raw-token"), "raw-token");
        assert_eq!(extract_bearer_or_value("  x  "), "x");
    }
}
