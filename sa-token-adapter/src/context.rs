// Author: 金书记
//
//! 请求/响应上下文适配器trait定义

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 请求上下文trait
///
/// 各个Web框架需要为其Request类型实现这个trait
pub trait SaRequest {
    /// 获取请求头
    fn get_header(&self, name: &str) -> Option<String>;

    /// 获取所有请求头
    fn get_headers(&self) -> HashMap<String, String> {
        HashMap::new() // 默认实现
    }

    /// 获取Cookie
    fn get_cookie(&self, name: &str) -> Option<String>;

    /// 获取所有Cookie
    fn get_cookies(&self) -> HashMap<String, String> {
        HashMap::new() // 默认实现
    }

    /// 获取查询参数
    fn get_param(&self, name: &str) -> Option<String>;

    /// 获取所有查询参数
    fn get_params(&self) -> HashMap<String, String> {
        HashMap::new() // 默认实现
    }

    /// 获取请求路径
    fn get_path(&self) -> String;

    /// 获取请求方法
    fn get_method(&self) -> String;

    /// 获取请求URI
    fn get_uri(&self) -> String {
        self.get_path()
    }

    /// 获取请求体（如果是JSON）
    fn get_body_json<T: for<'de> Deserialize<'de>>(&self) -> Option<T> {
        None // 默认实现
    }

    /// 获取客户端IP
    fn get_client_ip(&self) -> Option<String> {
        None // 默认实现
    }

    /// 获取User-Agent
    fn get_user_agent(&self) -> Option<String> {
        self.get_header("user-agent")
    }
}

/// 响应上下文trait
///
/// 各个Web框架需要为其Response类型实现这个trait
pub trait SaResponse {
    /// 设置响应头
    fn set_header(&mut self, name: &str, value: &str);

    /// 设置Cookie
    fn set_cookie(&mut self, name: &str, value: &str, options: CookieOptions);

    /// 删除Cookie
    fn delete_cookie(&mut self, name: &str) {
        self.set_cookie(
            name,
            "",
            CookieOptions {
                max_age: Some(0),
                ..Default::default()
            },
        );
    }

    /// 设置状态码
    fn set_status(&mut self, status: u16);

    /// 设置响应体（JSON）
    fn set_json_body<T: Serialize>(&mut self, body: T) -> Result<(), serde_json::Error>;
}

/// Cookie 选项
#[derive(Debug, Clone, Default)]
pub struct CookieOptions {
    /// 域名
    pub domain: Option<String>,

    /// 路径
    pub path: Option<String>,

    /// 过期时间（秒）
    pub max_age: Option<i64>,

    /// 是否仅HTTP
    pub http_only: bool,

    /// 是否安全（仅HTTPS）
    pub secure: bool,

    /// SameSite属性
    pub same_site: Option<SameSite>,
}

/// SameSite 属性 | SameSite attribute
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SameSite {
    /// Strict
    Strict,
    /// Lax
    Lax,
    /// None (requires Secure in browsers)
    /// None（浏览器通常要求 Secure）
    None,
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SameSite::Strict => write!(f, "Strict"),
            SameSite::Lax => write!(f, "Lax"),
            SameSite::None => write!(f, "None"),
        }
    }
}
