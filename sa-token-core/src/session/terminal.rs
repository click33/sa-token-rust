// Author: 金书记
//
//! Login device / terminal row for multi-device sessions.
//! 登录设备终端信息（多端会话）。
//!
//! 记录某账号某次登录所用的设备：第几个登录(index)、token、设备类型、设备唯一标识、
//! 登录时挂载的扩展数据、创建时间。终端信息随 Account-Session 一并持久化。

use serde::{Deserialize, Serialize};

/// 登录设备终端信息
///
/// 不 derive Eq——extra_data 含 serde_json::Value（浮点数不满足 Eq）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SaTerminalInfo {
    /// 登录会话索引值：该账号第几个登录的设备，从 1 开始
    pub index: i32,
    /// 此终端持有的 token 值
    pub token_value: String,
    /// 设备类型，例如 PC / WEB / MOBILE / APP；未指定时为空串
    pub device_type: String,
    /// 登录设备唯一标识（可选）
    pub device_id: Option<String>,
    /// 登录时挂载的扩展数据（只建议登录前设定）
    pub extra_data: Option<serde_json::Value>,
    /// Created-at timestamp (Unix millis).
    /// 创建时间（Unix 毫秒）。
    pub create_time: i64,
}

impl SaTerminalInfo {
    /// 新建终端信息；`index` 由 `SaSession::add_terminal` 自动分配，此处传 0 占位即可
    pub fn new(token_value: impl Into<String>, device_type: impl Into<String>) -> Self {
        Self {
            index: 0,
            token_value: token_value.into(),
            device_type: device_type.into(),
            device_id: None,
            extra_data: None,
            create_time: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// 链式设置设备唯一标识
    pub fn with_device_id(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    /// 链式设置扩展数据
    pub fn with_extra_data(mut self, extra: serde_json::Value) -> Self {
        self.extra_data = Some(extra);
        self
    }

    /// True when non-empty extra data is set.
    /// 是否设置了非空扩展数据。
    pub fn have_extra_data(&self) -> bool {
        matches!(&self.extra_data, Some(v) if !v.is_null())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_new_defaults() {
        let t = SaTerminalInfo::new("tok1", "PC");
        assert_eq!(t.index, 0);
        assert_eq!(t.token_value, "tok1");
        assert_eq!(t.device_type, "PC");
        assert!(t.device_id.is_none());
        assert!(!t.have_extra_data());
        assert!(t.create_time > 0);
    }

    #[test]
    fn test_with_extra_data() {
        let t = SaTerminalInfo::new("tok1", "APP").with_extra_data(json!({"k": 1}));
        assert!(t.have_extra_data());
    }

    #[test]
    fn test_serde_round_trip() {
        let t = SaTerminalInfo::new("tok1", "PC")
            .with_device_id("dev-1")
            .with_extra_data(json!({"ip": "127.0.0.1"}));
        let json = serde_json::to_string(&t).unwrap();
        let back: SaTerminalInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}
