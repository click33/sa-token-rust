// Author: 金书记
//
//! Session 管理模块

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod terminal;
pub use terminal::SaTerminalInfo;

/// Session 对象 | Session Object
///
/// 用于存储用户会话数据的对象
/// Object for storing user session data
///
/// # 字段说明 | Field Description
/// - `id`: Session 唯一标识 | Session unique identifier
/// - `create_time`: 创建时间 | Creation time
/// - `data`: 存储的键值对数据 | Stored key-value data
///
/// # 使用示例 | Usage Example
///
/// ```rust,ignore
/// let mut session = SaSession::new("session_123");
/// session.set("username", "张三")?;
/// session.set("age", 25)?;
///
/// let username: Option<String> = session.get("username");
/// println!("Username: {:?}", username);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaSession {
    /// Session ID
    pub id: String,

    /// 创建时间 | Creation time
    pub create_time: DateTime<Utc>,

    /// Logged-in device terminal list.
    /// 已登录设备终端列表。
    #[serde(default)]
    pub terminal_list: Vec<SaTerminalInfo>,

    /// Cumulative login-device count (monotonic); used for terminal index.
    /// 历史累计登录设备数，仅增不减，用于生成终端 index。
    #[serde(default)]
    pub history_terminal_count: i32,

    /// 数据存储 | Data storage
    #[serde(flatten)]
    pub data: HashMap<String, serde_json::Value>,
}

impl SaSession {
    /// Create a new instance | 创建新实例
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            create_time: Utc::now(),
            terminal_list: Vec::new(),
            history_terminal_count: 0,
            data: HashMap::new(),
        }
    }

    /// 设置值 | Set Value
    ///
    /// # 参数 | Parameters
    /// - `key`: 键名 | Key name
    /// - `value`: 要存储的值 | Value to store
    ///
    /// # 返回 | Returns
    /// - `Ok(())`: 设置成功 | Set successfully
    /// - `Err`: 序列化失败 | Serialization failed
    pub fn set<T: Serialize>(
        &mut self,
        key: impl Into<String>,
        value: T,
    ) -> Result<(), serde_json::Error> {
        let json_value = serde_json::to_value(value)?;
        self.data.insert(key.into(), json_value);
        Ok(())
    }

    /// 获取值 | Get Value
    ///
    /// # 参数 | Parameters
    /// - `key`: 键名 | Key name
    ///
    /// # 返回 | Returns
    /// - `Some(value)`: 找到值并成功反序列化 | Found value and deserialized successfully
    /// - `None`: 键不存在或反序列化失败 | Key not found or deserialization failed
    pub fn get<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.data
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// 删除值 | Remove Value
    ///
    /// # 参数 | Parameters
    /// - `key`: 键名 | Key name
    ///
    /// # 返回 | Returns
    /// 被删除的值，如果键不存在则返回 None
    /// Removed value, or None if key doesn't exist
    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.data.remove(key)
    }

    /// 清空 session | Clear Session
    ///
    /// 删除所有存储的数据 | Remove all stored data
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// 检查 key 是否存在 | Check if Key Exists
    ///
    /// # 参数 | Parameters
    /// - `key`: 键名 | Key name
    ///
    /// # 返回 | Returns
    /// - `true`: 键存在 | Key exists
    /// - `false`: 键不存在 | Key doesn't exist
    pub fn has(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// 新增一个终端：自动分配 index = history_terminal_count + 1，并累加历史计数
    pub fn add_terminal(&mut self, mut terminal: SaTerminalInfo) {
        self.history_terminal_count += 1;
        terminal.index = self.history_terminal_count;
        self.terminal_list.push(terminal);
    }

    /// 按 token 移除终端；返回被移除的终端（不存在则 None）
    pub fn remove_terminal(&mut self, token_value: &str) -> Option<SaTerminalInfo> {
        if let Some(pos) = self
            .terminal_list
            .iter()
            .position(|t| t.token_value == token_value)
        {
            Some(self.terminal_list.remove(pos))
        } else {
            None
        }
    }

    /// 按 token 获取终端引用
    pub fn get_terminal(&self, token_value: &str) -> Option<&SaTerminalInfo> {
        self.terminal_list
            .iter()
            .find(|t| t.token_value == token_value)
    }

    /// 终端列表副本
    pub fn terminal_list_copy(&self) -> Vec<SaTerminalInfo> {
        self.terminal_list.clone()
    }

    /// 按设备类型筛选终端；device_type 传 None 表示不限设备类型
    pub fn get_terminal_list_by_device_type(
        &self,
        device_type: Option<&str>,
    ) -> Vec<SaTerminalInfo> {
        match device_type {
            None => self.terminal_list.clone(),
            Some(dt) => self
                .terminal_list
                .iter()
                .filter(|t| t.device_type == dt)
                .cloned()
                .collect(),
        }
    }

    /// 按设备类型提取 token 列表
    pub fn get_token_value_list_by_device_type(&self, device_type: Option<&str>) -> Vec<String> {
        self.get_terminal_list_by_device_type(device_type)
            .into_iter()
            .map(|t| t.token_value)
            .collect()
    }

    /// 终端数量
    pub fn terminal_count(&self) -> usize {
        self.terminal_list.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_index_increments() {
        let mut session = SaSession::new("u1");
        session.add_terminal(SaTerminalInfo::new("t1", "PC"));
        session.add_terminal(SaTerminalInfo::new("t2", "APP"));
        session.add_terminal(SaTerminalInfo::new("t3", "WEB"));
        assert_eq!(session.terminal_count(), 3);
        assert_eq!(session.history_terminal_count, 3);
        assert_eq!(session.terminal_list[0].index, 1);
        assert_eq!(session.terminal_list[1].index, 2);
        assert_eq!(session.terminal_list[2].index, 3);

        session.remove_terminal("t2");
        session.add_terminal(SaTerminalInfo::new("t4", "PC"));
        assert_eq!(session.terminal_list.last().unwrap().index, 4);
    }

    #[test]
    fn test_filter_by_device_type() {
        let mut session = SaSession::new("u1");
        session.add_terminal(SaTerminalInfo::new("t1", "PC"));
        session.add_terminal(SaTerminalInfo::new("t2", "PC"));
        session.add_terminal(SaTerminalInfo::new("t3", "APP"));
        assert_eq!(
            session.get_terminal_list_by_device_type(Some("PC")).len(),
            2
        );
        assert_eq!(session.get_terminal_list_by_device_type(None).len(), 3);
        assert_eq!(
            session.get_token_value_list_by_device_type(Some("APP")),
            vec!["t3".to_string()]
        );
    }

    #[test]
    fn test_deserialize_legacy_session_without_terminals() {
        let json = r#"{"id":"u1","create_time":"2024-01-01T00:00:00Z","foo":"bar"}"#;
        let session: SaSession = serde_json::from_str(json).unwrap();
        assert!(session.terminal_list.is_empty());
        assert_eq!(session.history_terminal_count, 0);
    }
}
