// Author: 金书记
//
//! Token 管理模块

use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

mod csprng;
pub mod generator;
pub mod jwt;
pub mod map;
pub mod validator;

pub(crate) use csprng::random_hex;
pub use generator::{TokenGenerator, generate_unique};
pub use jwt::{JwtAlgorithm, JwtClaims, JwtManager};
pub use validator::TokenValidator;

/// Token 字节在请求内会被 TokenInfo / 上下文多次 Clone；用 Arc 避免复制。
/// Token bytes are cloned across TokenInfo and request context; Arc avoids copying.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenValue(Arc<str>);

impl TokenValue {
    /// Create a new instance | 创建新实例
    pub fn new(value: impl AsRef<str>) -> Self {
        Self(Arc::from(value.as_ref()))
    }

    /// `as_str` — as str | `as_str`
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for TokenValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TokenValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self(Arc::from(s)))
    }
}

impl From<String> for TokenValue {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl From<&str> for TokenValue {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
    }
}

impl From<TokenValue> for String {
    fn from(v: TokenValue) -> Self {
        v.0.to_string()
    }
}

impl std::fmt::Display for TokenValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 默认账号体系字符串只 intern 一次。这是 OnceLock 的正确用途（常量），不是替代 Arc。
/// Intern the default login-type string once. A legitimate OnceLock use (a constant), not an Arc replacement.
pub fn intern_login_type(s: &str) -> Arc<str> {
    if s.is_empty() || s == crate::keys::LOGIN_TYPE_DEFAULT || s == "login" {
        static DEFAULT: OnceLock<Arc<str>> = OnceLock::new();
        return DEFAULT
            .get_or_init(|| Arc::from(crate::keys::LOGIN_TYPE_DEFAULT))
            .clone();
    }
    Arc::from(s)
}

/// Serde helpers for `Arc<str>` (serde has no built-in Arc<str> without `rc` + owned form).
/// `Arc<str>` 的 serde 辅助（无内置支持时走 String 往返）。
mod arc_str_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::sync::Arc;

    pub(super) fn serialize<S: Serializer>(
        value: &Arc<str>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Arc<str>, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Arc::from(s))
    }
}

/// Token 信息 | Token Information
///
/// 存储 Token 的完整信息，包括元数据和安全特性
/// Stores complete token information, including metadata and security features
///
/// # 字段说明 | Field Description
/// - `token`: Token 值 | Token value
/// - `login_id`: 登录用户 ID | Logged-in user ID
/// - `login_type`: 登录类型（如 "user", "admin"）| Login type (e.g., "user", "admin")
/// - `create_time`: Token 创建时间 | Token creation time
/// - `last_active_time`: 最后活跃时间 | Last active time
/// - `expire_time`: 过期时间（None 表示永不过期）| Expiration time (None means never expires)
/// - `device`: 设备标识 | Device identifier
/// - `extra_data`: 额外数据 | Extra data
/// - `nonce`: 防重放攻击的一次性令牌 | One-time token for replay attack prevention
/// - `refresh_token`: 用于刷新的长期令牌 | Long-term token for refresh
/// - `refresh_token_expire_time`: Refresh Token 过期时间 | Refresh token expiration time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token 值 | Token value
    pub token: TokenValue,

    /// 登录 ID（Arc 共享，避免请求内多次 Clone 拷贝字节）
    /// Login ID (Arc-shared to avoid copying bytes on request-path clones)
    #[serde(with = "arc_str_serde")]
    pub login_id: Arc<str>,

    /// 登录类型（默认体系经 [`intern_login_type`] 复用同一 Arc）
    /// Login type (default systems reuse one Arc via [`intern_login_type`])
    #[serde(with = "arc_str_serde")]
    pub login_type: Arc<str>,

    /// Token 创建时间 | Token creation time
    pub create_time: DateTime<Utc>,

    /// Token 最后活跃时间 | Token last active time
    pub last_active_time: DateTime<Utc>,

    /// Token 过期时间（None 表示永不过期）| Token expiration time (None means never expires)
    pub expire_time: Option<DateTime<Utc>>,

    /// 设备标识 | Device identifier
    pub device: Option<String>,

    /// 额外数据 | Extra data
    pub extra_data: Option<serde_json::Value>,

    /// Nonce（用于防重放攻击）| Nonce (for replay attack prevention)
    pub nonce: Option<String>,

    /// Refresh Token（用于刷新访问令牌）| Refresh Token (for refreshing access token)
    pub refresh_token: Option<String>,

    /// Refresh Token 过期时间 | Refresh Token expiration time
    pub refresh_token_expire_time: Option<DateTime<Utc>>,

    /// Per-token idle timeout (seconds). Used only when `dynamic_active_timeout` is on.
    /// 单 token 闲置超时（秒）。仅 `dynamic_active_timeout` 打开时使用。
    #[serde(default)]
    pub active_timeout_override: Option<i64>,
}

impl TokenInfo {
    /// Create a new instance | 创建新实例
    pub fn new(token: TokenValue, login_id: impl AsRef<str>) -> Self {
        let now = Utc::now();
        Self {
            token,
            login_id: Arc::from(login_id.as_ref()),
            login_type: intern_login_type(crate::keys::LOGIN_TYPE_DEFAULT),
            create_time: now,
            last_active_time: now,
            expire_time: None,
            device: None,
            extra_data: None,
            nonce: None,
            refresh_token: None,
            refresh_token_expire_time: None,
            active_timeout_override: None,
        }
    }

    /// Idle limit actually used for freeze checks.
    /// 冻结检查实际使用的闲置上限。
    pub fn effective_active_timeout(&self, config: &crate::config::SaTokenConfig) -> i64 {
        if config.dynamic_active_timeout {
            self.active_timeout_override
                .unwrap_or(config.active_timeout)
        } else {
            config.active_timeout
        }
    }

    /// `is_expired` — is expired | `is_expired`
    pub fn is_expired(&self) -> bool {
        if let Some(expire_time) = self.expire_time {
            Utc::now() > expire_time
        } else {
            false
        }
    }

    /// `update_active_time` — update active time | `update_active_time`
    pub fn update_active_time(&mut self) {
        self.last_active_time = Utc::now();
    }

    /// True when idle longer than `active_timeout`.
    /// 空闲超过 `active_timeout` 时为 true。
    ///
    /// `active_timeout <= 0` means never freeze; otherwise compares now vs `last_active_time`.
    pub fn is_freeze(&self, active_timeout: i64) -> bool {
        if active_timeout <= 0 {
            return false;
        }
        Utc::now()
            .signed_duration_since(self.last_active_time)
            .num_seconds()
            > active_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_freeze_respects_active_timeout() {
        let mut info = TokenInfo::new(TokenValue::new("t"), "u");
        info.last_active_time = Utc::now() - chrono::Duration::seconds(120);
        assert!(info.is_freeze(60));
        assert!(!info.is_freeze(-1));
        assert!(!info.is_freeze(0));
    }
}

/// Token 签名
#[derive(Debug, Clone)]
pub struct TokenSign {
    /// `value` | `value`
    pub value: String,
    /// Device / terminal label | 设备/终端标识
    pub device: Option<String>,
}
