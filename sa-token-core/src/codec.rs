// Author: 金书记
//
//! Pluggable serialization helpers | 可插拔序列化辅助函数
//!
//! Thin wrappers around [`SharedSerializer`] that map errors into [`SaTokenError`].
//! Prefer these when a module holds a serializer but not full [`SaTokenConfig`].
//! 对 [`SharedSerializer`] 的薄封装，将错误映射为 [`SaTokenError`]。
//! 模块仅持有序列化器、无完整 config 时优先使用。

use sa_token_adapter::serializer::SharedSerializer;
use serde::{Serialize, de::DeserializeOwned};

use crate::error::{SaTokenError, SaTokenResult};

/// Encode object to storage string | 将对象编码为存储字符串
#[inline]
pub fn encode_value<T: Serialize + ?Sized>(
    serializer: &SharedSerializer,
    value: &T,
) -> SaTokenResult<String> {
    serializer.encode(value).map_err(SaTokenError::from)
}

/// Decode storage string; auto-detects JSON / binary magic | 解码存储字符串；自动探测 JSON / 二进制魔数
#[inline]
pub fn decode_value<T: DeserializeOwned>(
    serializer: &SharedSerializer,
    raw: &str,
) -> SaTokenResult<T> {
    serializer.decode(raw).map_err(SaTokenError::from)
}
