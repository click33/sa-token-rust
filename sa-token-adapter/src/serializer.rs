// Author: 金书记 | Author: Jin Shuji
//
//! Pluggable Serialization Trait and Implementations | 可插拔序列化 trait 与实现
//!
//! Unified encode/decode for storage payloads with rolling-upgrade support
//! (JSON default, optional fory binary). | 统一存储编解码，支持滚动升级（默认 JSON，可选 fory 二进制）。
//!
//! ## Design Goals | 设计目标
//!
//! 1. **Format Agnostic**: JSON (default), binary (`fory`), future formats
//!    **格式无关**：JSON（默认）、二进制（`fory`）、未来格式
//! 2. **Bytes Path**: `encode_bytes` / `decode_bytes` for Redis-friendly payloads
//!    **字节路径**：面向 Redis 等场景的 `encode_bytes` / `decode_bytes`
//! 3. **Rolling Upgrade**: Read path auto-detects legacy JSON + magic-prefixed binary
//!    **滚动升级**：读路径自动探测存量 JSON + 魔数前缀二进制
//! 4. **Fine-Grained Errors**: `EncodeFailed` / `DecodeFailed` / `FormatMismatch` / `VersionIncompatible`
//!    **精细错误**：编码失败 / 解码失败 / 格式不匹配 / 版本不兼容
//!
//! Prefer [`SharedSerializer`] at call sites (Clone-friendly enum, no trait object).
//! 调用方优先使用 [`SharedSerializer`]（Clone 友好枚举，无 trait object）。

use serde::{Serialize, de::DeserializeOwned};

/// Storage value encoding format | 存储值编码格式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    /// Pure JSON text (no prefix, compatible with existing data) | 纯 JSON 文本（无前缀，兼容存量数据）
    Json,
    /// fory binary Base64-encoded with magic prefix | fory 二进制经 Base64 编码并带魔数前缀
    Binary,
}

/// Serializer error (A2-2: fine-grained variants) | 序列化错误（A2-2：精细错误变体）
///
/// - `EncodeFailed`: serde encode failure — log data model, do not retry
///   编码失败：记录数据模型问题，不要重试
/// - `DecodeFailed`: malformed payload — log and consider fallback/migration
///   解码失败：记录并考虑降级/迁移
/// - `FormatMismatch`: e.g. JsonSerializer sees binary magic — check config
///   格式不匹配：检查序列化器配置
/// - `VersionIncompatible`: reserved for schema evolution
///   版本不兼容：预留模式演进
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerializerError {
    /// Encoding failed | 编码失败
    EncodeFailed(String),
    /// Decoding failed | 解码失败
    DecodeFailed(String),
    /// Format mismatch between serializer and payload | 序列化器与 payload 格式不匹配
    FormatMismatch {
        /// Expected format name | 期望格式名
        expected: &'static str,
        /// Actual detected format | 实际探测到的格式
        actual: &'static str,
    },
    /// Version incompatible (future schema evolution) | 版本不兼容（未来模式演进）
    VersionIncompatible,
}

impl std::fmt::Display for SerializerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncodeFailed(msg) => write!(f, "Serialization encoding failed: {msg}"),
            Self::DecodeFailed(msg) => write!(f, "Serialization decoding failed: {msg}"),
            Self::FormatMismatch { expected, actual } => {
                write!(f, "Format mismatch: expected {expected}, got {actual}")
            }
            Self::VersionIncompatible => {
                write!(f, "Version incompatible: stored data version is too new")
            }
        }
    }
}

impl std::error::Error for SerializerError {}

/// Pluggable serializer: domain object ↔ storage string | 可插拔序列化器：领域对象 ↔ 存储字符串
///
/// # Methods | 方法
/// - `name` / `kind` / `encode` / `decode` — core String path | 核心 String 路径
/// - `encode_bytes` / `decode_bytes` — optional zero-copy path (A2-3) | 可选零拷贝路径
pub trait SaSerializer: Send + Sync {
    /// Serializer identifier (e.g. "json", "fory") | 序列化器标识
    fn name(&self) -> &'static str;

    /// Detect payload format for rolling upgrades | 探测 payload 格式以支持滚动升级
    fn kind(&self, raw: &str) -> ValueKind;

    /// Encode domain object to storage string | 编码领域对象为存储字符串
    ///
    /// Errors: `EncodeFailed` on serde failure | 错误：serde 失败时 `EncodeFailed`
    fn encode<T: Serialize + ?Sized>(&self, value: &T) -> Result<String, SerializerError>;

    /// Decode storage string to domain object | 解码存储字符串为领域对象
    ///
    /// Errors: `DecodeFailed` / `FormatMismatch` | 错误：`DecodeFailed` / `FormatMismatch`
    fn decode<T: DeserializeOwned>(&self, raw: &str) -> Result<T, SerializerError>;

    /// Encode to bytes (default: UTF-8 of `encode`) | 编码为 bytes（默认委托 `encode`）
    #[inline]
    fn encode_bytes<T: Serialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>, SerializerError> {
        self.encode(value).map(|s| s.into_bytes())
    }

    /// Decode from bytes (default: UTF-8 then `decode`) | 从 bytes 解码（默认 UTF-8 再 `decode`）
    #[inline]
    fn decode_bytes<T: DeserializeOwned>(&self, bytes: &[u8]) -> Result<T, SerializerError> {
        let s = std::str::from_utf8(bytes)
            .map_err(|e| SerializerError::DecodeFailed(format!("Invalid UTF-8: {e}")))?;
        self.decode(s)
    }
}

/// Binary payload magic (`\u{0001}STF`) | 二进制 payload 魔数
pub const BINARY_MAGIC: &str = "\u{0001}STF";

/// JSON serializer configuration (A2-4) | JSON 序列化器配置（A2-4）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JsonSerializerConfig {
    /// Pretty-print JSON (dev only) | 美化打印（仅开发）
    pub pretty_print: bool,
    /// Escape non-ASCII (reserved) | 转义非 ASCII（预留）
    pub escape_unicode: bool,
}

/// Default JSON serializer | 默认 JSON 序列化器
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonSerializer {
    config: JsonSerializerConfig,
}

impl JsonSerializer {
    /// Create with custom config (A2-4) | 使用自定义配置创建（A2-4）
    pub fn with_config(config: JsonSerializerConfig) -> Self {
        Self { config }
    }
}

impl SaSerializer for JsonSerializer {
    #[inline]
    fn name(&self) -> &'static str {
        "json"
    }

    #[inline]
    fn kind(&self, raw: &str) -> ValueKind {
        if raw.starts_with(BINARY_MAGIC) {
            ValueKind::Binary
        } else {
            ValueKind::Json
        }
    }

    #[inline]
    fn encode<T: Serialize + ?Sized>(&self, value: &T) -> Result<String, SerializerError> {
        if self.config.pretty_print {
            serde_json::to_string_pretty(value)
                .map_err(|e| SerializerError::EncodeFailed(e.to_string()))
        } else {
            serde_json::to_string(value).map_err(|e| SerializerError::EncodeFailed(e.to_string()))
        }
    }

    #[inline]
    fn decode<T: DeserializeOwned>(&self, raw: &str) -> Result<T, SerializerError> {
        if raw.starts_with(BINARY_MAGIC) {
            return Err(SerializerError::FormatMismatch {
                expected: "json",
                actual: "binary",
            });
        }
        serde_json::from_str(raw).map_err(|e| SerializerError::DecodeFailed(e.to_string()))
    }

    #[inline]
    fn encode_bytes<T: Serialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>, SerializerError> {
        if self.config.pretty_print {
            serde_json::to_vec_pretty(value)
                .map_err(|e| SerializerError::EncodeFailed(e.to_string()))
        } else {
            serde_json::to_vec(value).map_err(|e| SerializerError::EncodeFailed(e.to_string()))
        }
    }
}

#[cfg(feature = "fory")]
mod fory_impl {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use fory::Fory;
    use std::sync::OnceLock;

    fn fory_runtime() -> &'static Fory {
        static RUNTIME: OnceLock<Fory> = OnceLock::new();
        RUNTIME.get_or_init(Fory::default)
    }

    /// Fory serializer configuration (A2-4) | Fory 序列化器配置（A2-4）
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ForySerializerConfig {
        /// Compression level 0-9 (documented; runtime may ignore) | 压缩级别 0-9（文档项，运行时可能忽略）
        pub compression_level: u8,
    }

    impl Default for ForySerializerConfig {
        fn default() -> Self {
            Self {
                compression_level: 6,
            }
        }
    }

    /// fory binary serializer (feature `fory`) | fory 二进制序列化器
    #[derive(Debug, Clone, Copy, Default)]
    pub struct ForySerializer {
        #[allow(dead_code)]
        config: ForySerializerConfig,
    }

    impl ForySerializer {
        /// Create with custom config | 使用自定义配置创建
        pub fn with_config(config: ForySerializerConfig) -> Self {
            Self { config }
        }
    }

    impl SaSerializer for ForySerializer {
        #[inline]
        fn name(&self) -> &'static str {
            "fory"
        }

        #[inline]
        fn kind(&self, raw: &str) -> ValueKind {
            if raw.starts_with(BINARY_MAGIC) {
                ValueKind::Binary
            } else {
                ValueKind::Json
            }
        }

        fn encode<T: Serialize + ?Sized>(&self, value: &T) -> Result<String, SerializerError> {
            let json = serde_json::to_string(value)
                .map_err(|e| SerializerError::EncodeFailed(e.to_string()))?;
            let bytes = fory_runtime()
                .serialize(&json)
                .map_err(|e| SerializerError::EncodeFailed(e.to_string()))?;
            Ok(format!("{}{}", super::BINARY_MAGIC, STANDARD.encode(bytes)))
        }

        fn decode<T: DeserializeOwned>(&self, raw: &str) -> Result<T, SerializerError> {
            if raw.starts_with(BINARY_MAGIC) {
                let b64 = &raw[super::BINARY_MAGIC.len()..];
                let bytes = STANDARD
                    .decode(b64)
                    .map_err(|e| SerializerError::DecodeFailed(e.to_string()))?;
                let json: String = fory_runtime()
                    .deserialize(&bytes)
                    .map_err(|e| SerializerError::DecodeFailed(e.to_string()))?;
                serde_json::from_str(&json)
                    .map_err(|e| SerializerError::DecodeFailed(e.to_string()))
            } else {
                // Rolling upgrade: legacy pure JSON | 滚动升级：存量纯 JSON
                serde_json::from_str(raw).map_err(|e| SerializerError::DecodeFailed(e.to_string()))
            }
        }

        fn encode_bytes<T: Serialize + ?Sized>(
            &self,
            value: &T,
        ) -> Result<Vec<u8>, SerializerError> {
            let json = serde_json::to_string(value)
                .map_err(|e| SerializerError::EncodeFailed(e.to_string()))?;
            fory_runtime()
                .serialize(&json)
                .map_err(|e| SerializerError::EncodeFailed(e.to_string()))
        }

        fn decode_bytes<T: DeserializeOwned>(&self, bytes: &[u8]) -> Result<T, SerializerError> {
            let json: String = fory_runtime()
                .deserialize(bytes)
                .map_err(|e| SerializerError::DecodeFailed(e.to_string()))?;
            serde_json::from_str(&json).map_err(|e| SerializerError::DecodeFailed(e.to_string()))
        }
    }
}

#[cfg(feature = "fory")]
pub use fory_impl::{ForySerializer, ForySerializerConfig};

/// Shared serializer handle (Clone-friendly enum) | 共享序列化器句柄（Clone 友好枚举）
#[derive(Clone)]
pub enum SharedSerializer {
    /// Default JSON | 默认 JSON
    Json(JsonSerializer),
    /// fory binary (feature `fory`) | fory 二进制
    #[cfg(feature = "fory")]
    Fory(ForySerializer),
}

impl Default for SharedSerializer {
    fn default() -> Self {
        Self::Json(JsonSerializer::default())
    }
}

impl std::fmt::Debug for SharedSerializer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSerializer({})", self.name())
    }
}

impl SharedSerializer {
    /// Serializer name | 序列化器名称
    #[inline]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Json(s) => s.name(),
            #[cfg(feature = "fory")]
            Self::Fory(s) => s.name(),
        }
    }

    /// Detect value kind | 探测值格式
    #[inline]
    pub fn kind(&self, raw: &str) -> ValueKind {
        match self {
            Self::Json(s) => s.kind(raw),
            #[cfg(feature = "fory")]
            Self::Fory(s) => s.kind(raw),
        }
    }

    /// Encode domain object | 编码领域对象
    #[inline]
    pub fn encode<T: Serialize + ?Sized>(&self, value: &T) -> Result<String, SerializerError> {
        match self {
            Self::Json(s) => s.encode(value),
            #[cfg(feature = "fory")]
            Self::Fory(s) => s.encode(value),
        }
    }

    /// Decode storage string | 解码存储字符串
    #[inline]
    pub fn decode<T: DeserializeOwned>(&self, raw: &str) -> Result<T, SerializerError> {
        match self {
            Self::Json(s) => s.decode(raw),
            #[cfg(feature = "fory")]
            Self::Fory(s) => s.decode(raw),
        }
    }

    /// Encode to bytes | 编码为 bytes
    #[inline]
    pub fn encode_bytes<T: Serialize + ?Sized>(
        &self,
        value: &T,
    ) -> Result<Vec<u8>, SerializerError> {
        match self {
            Self::Json(s) => s.encode_bytes(value),
            #[cfg(feature = "fory")]
            Self::Fory(s) => s.encode_bytes(value),
        }
    }

    /// Decode from bytes | 从 bytes 解码
    #[inline]
    pub fn decode_bytes<T: DeserializeOwned>(&self, bytes: &[u8]) -> Result<T, SerializerError> {
        match self {
            Self::Json(s) => s.decode_bytes(bytes),
            #[cfg(feature = "fory")]
            Self::Fory(s) => s.decode_bytes(bytes),
        }
    }

    /// Borrow as JsonSerializer if variant matches | 若为 JSON 变体则借用
    #[inline]
    pub fn as_json(&self) -> Option<&JsonSerializer> {
        match self {
            Self::Json(s) => Some(s),
            #[cfg(feature = "fory")]
            _ => None,
        }
    }

    /// Borrow as ForySerializer if variant matches | 若为 fory 变体则借用
    #[cfg(feature = "fory")]
    #[inline]
    pub fn as_fory(&self) -> Option<&ForySerializer> {
        match self {
            Self::Fory(s) => Some(s),
            _ => None,
        }
    }
}

impl From<JsonSerializer> for SharedSerializer {
    fn from(value: JsonSerializer) -> Self {
        Self::Json(value)
    }
}

#[cfg(feature = "fory")]
impl From<ForySerializer> for SharedSerializer {
    fn from(value: ForySerializer) -> Self {
        Self::Fory(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Sample {
        id: u32,
        name: String,
    }

    #[test]
    fn json_roundtrip() {
        let ser = SharedSerializer::default();
        let sample = Sample {
            id: 1,
            name: "alice".into(),
        };
        let raw = ser.encode(&sample).unwrap();
        assert_eq!(ser.kind(&raw), ValueKind::Json);
        assert_eq!(ser.decode::<Sample>(&raw).unwrap(), sample);
    }

    #[test]
    fn json_rejects_binary_magic() {
        let ser = SharedSerializer::default();
        let err = ser
            .decode::<Sample>(&format!("{BINARY_MAGIC}xxx"))
            .unwrap_err();
        assert!(matches!(
            err,
            SerializerError::FormatMismatch {
                expected: "json",
                actual: "binary"
            }
        ));
    }

    #[cfg(feature = "fory")]
    #[test]
    fn fory_roundtrip() {
        let ser = SharedSerializer::from(ForySerializer::default());
        let sample = Sample {
            id: 2,
            name: "bob".into(),
        };
        let raw = ser.encode(&sample).unwrap();
        assert_eq!(ser.kind(&raw), ValueKind::Binary);
        assert!(raw.starts_with(BINARY_MAGIC));
        assert_eq!(ser.decode::<Sample>(&raw).unwrap(), sample);
    }

    #[cfg(feature = "fory")]
    #[test]
    fn fory_reads_legacy_json() {
        let ser = SharedSerializer::from(ForySerializer::default());
        let json = r#"{"id":3,"name":"carol"}"#;
        assert_eq!(ser.kind(json), ValueKind::Json);
        assert_eq!(
            ser.decode::<Sample>(json).unwrap(),
            Sample {
                id: 3,
                name: "carol".into(),
            }
        );
    }
}
