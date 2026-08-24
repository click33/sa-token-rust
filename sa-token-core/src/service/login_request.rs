//! 登录参数对象，替代 manager 上 6 个 `Option` 位置参数。
//!
//! 原 `login_with_options` 有 6 个连续的 `Option` 参数，调用方极易错位传参
//! （`device` 与 `nonce` 类型相同，写反了编译器也不会报错）。改为具名 Builder
//! 后错位传参成为编译期不可能，且新增可选字段不再是破坏性变更。
//!
//! Parameter object replacing the six positional `Option` arguments of
//! `login_with_options`. Adjacent same-typed options made argument swaps easy
//! and invisible to the compiler; a named builder makes them impossible and
//! turns future optional fields into non-breaking additions.

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::keys::LOGIN_TYPE_DEFAULT;

/// 登录请求（Builder 风格构造）| Login request, built builder-style
#[derive(Debug, Clone)]
pub struct LoginRequest {
    /// 登录账号 ID（原始值，未做命名空间拼接）| Raw login id, not namespaced
    pub login_id: String,
    /// 登录类型，多账号体系隔离维度 | Login type, the multi-account isolation axis
    pub login_type: String,
    /// 设备类型标识（如 "PC" / "APP"）| Device type such as "PC" or "APP"
    pub device: Option<String>,
    /// 附加数据，会写入 TokenInfo 与终端信息 | Extra payload stored on the token
    pub extra_data: Option<Value>,
    /// 一次性防重放令牌 | One-shot anti-replay nonce
    pub nonce: Option<String>,
    /// 自定义过期时间，缺省时由 config.timeout 推导
    /// Custom expiry; derived from `config.timeout` when absent
    pub expire_time: Option<DateTime<Utc>>,
    /// 调用方预置的 token 值（SSO / 迁移场景复用既有 token）。
    /// 为空字符串时视为未预置，由服务层生成。
    /// Caller-supplied token value (SSO / migration); an empty string means
    /// "not preset" and the service layer will generate one.
    pub preset_token: Option<String>,
}

impl LoginRequest {
    /// 以账号 ID 创建请求，其余字段取默认值。
    /// Create a request from a login id, leaving the rest at their defaults.
    pub fn new(login_id: impl Into<String>) -> Self {
        Self {
            login_id: login_id.into(),
            // 使用 A3 统一常量，避免 "default" / "login" 硬编码漂移
            // Use the A3 constant to avoid hardcoded "default" / "login" drift
            login_type: LOGIN_TYPE_DEFAULT.to_string(),
            device: None,
            extra_data: None,
            nonce: None,
            expire_time: None,
            preset_token: None,
        }
    }

    /// 设置登录类型 | Set the login type
    pub fn login_type(mut self, login_type: impl Into<String>) -> Self {
        self.login_type = login_type.into();
        self
    }

    /// 设置设备类型 | Set the device type
    pub fn device(mut self, device: impl Into<String>) -> Self {
        self.device = Some(device.into());
        self
    }

    /// 设置附加数据 | Set the extra payload
    pub fn extra_data(mut self, data: Value) -> Self {
        self.extra_data = Some(data);
        self
    }

    /// 设置一次性 nonce | Set the one-shot nonce
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// 设置自定义过期时间 | Set a custom expiry
    pub fn expire_time(mut self, t: DateTime<Utc>) -> Self {
        self.expire_time = Some(t);
        self
    }

    /// 设置预置 token | Set a preset token value
    pub fn preset_token(mut self, token: impl Into<String>) -> Self {
        self.preset_token = Some(token.into());
        self
    }

    /// 规范化后的 login_type：空串一律回落到 `LOGIN_TYPE_DEFAULT`。
    ///
    /// 收敛点：整个登录链路只在此处判断"空 login_type 怎么办"，
    /// 避免 A3-19 那类「manager 用 "default"、StpUtil 用 "login"」的分叉。
    ///
    /// Normalized login type: an empty string always falls back to
    /// `LOGIN_TYPE_DEFAULT`. Single decision point, preventing the
    /// "manager says default, StpUtil says login" divergence found in A3-19.
    pub fn effective_login_type(&self) -> &str {
        if self.login_type.is_empty() {
            LOGIN_TYPE_DEFAULT
        } else {
            &self.login_type
        }
    }

    /// 规范化后的设备类型：`None` 与空串等价，均返回 `None`（修 B1-25）。
    ///
    /// 顶号范围判定依赖它：设备类型缺失时无法做"仅顶同设备"，
    /// 必须退化为全设备范围，否则会漏顶旧 token 造成越权。
    ///
    /// Normalized device type: `None` and `""` are equivalent. The replaced-range
    /// logic relies on this — without a device type, "current device only" is
    /// meaningless and must degrade to "all devices", otherwise stale tokens
    /// would survive a login that was supposed to replace them.
    pub fn effective_device(&self) -> Option<&str> {
        self.device.as_deref().filter(|d| !d.is_empty())
    }
}
