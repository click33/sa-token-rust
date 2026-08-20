// Author: 金书记 | Author: Jin Shuji
//! HMAC-SHA256 request signing (timestamp + optional nonce).
//! HMAC-SHA256 请求签名（时间戳 + 可选 nonce）。
//!
//! Shared by SSO HTTP and any open API that wants the same canonical query.
//! SSO HTTP 与需要同一套规范查询串的开放 API 共用本类型。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use crate::http_basic::ct_eq;

type HmacSha256 = Hmac<Sha256>;

/// Query/body signing helper.
/// 查询串/表单体签名。
#[derive(Clone)]
pub struct RequestSign {
    secret: String,
    window_secs: i64,
    dao: Option<Arc<SaTokenDao>>,
}

impl std::fmt::Debug for RequestSign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RequestSign { .. }")
    }
}

impl RequestSign {
    /// Create a signer with secret and timestamp window (seconds).
    /// 使用密钥与时间窗（秒）创建签名器。
    pub fn new(secret: impl Into<String>, window_secs: i64) -> Self {
        Self {
            secret: secret.into(),
            window_secs: if window_secs > 0 { window_secs } else { 300 },
            dao: None,
        }
    }

    /// Attach Dao so nonce values can be consumed once.
    /// 挂载 Dao，使 nonce 只能使用一次。
    pub fn with_dao(mut self, dao: Arc<SaTokenDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    fn canonical(params: &BTreeMap<String, String>) -> String {
        params
            .iter()
            .filter(|(k, _)| k.as_str() != "sign")
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// Hex HMAC-SHA256 over the canonical query (excludes the `sign` field).
    /// 对规范查询串做 Hex HMAC-SHA256（排除 `sign` 字段）。
    pub fn sign_params(&self, params: &BTreeMap<String, String>) -> SaTokenResult<String> {
        if self.secret.is_empty() {
            return Err(SaTokenError::ConfigError(
                "request sign secret is empty".into(),
            ));
        }
        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())
            .map_err(|e| SaTokenError::ConfigError(format!("invalid request sign secret: {e}")))?;
        mac.update(Self::canonical(params).as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Insert `timestamp` + `nonce` then compute `sign`. Caller sends the whole map.
    /// 写入 `timestamp` 与 `nonce` 再计算 `sign`。调用方发送完整 map。
    pub fn create_signed(
        &self,
        mut params: BTreeMap<String, String>,
    ) -> SaTokenResult<BTreeMap<String, String>> {
        let now = chrono::Utc::now().timestamp().to_string();
        let nonce = crate::token::random_hex(32)?;
        params.insert("timestamp".into(), now);
        params.insert("nonce".into(), nonce);
        let sign = self.sign_params(&params)?;
        params.insert("sign".into(), sign);
        Ok(params)
    }

    /// Verify signature, timestamp window, and optional nonce uniqueness.
    /// 校验签名、时间窗与可选 nonce 唯一性。
    pub async fn verify_params(
        &self,
        params: &BTreeMap<String, String>,
        provided_sign: &str,
    ) -> SaTokenResult<()> {
        if self.secret.is_empty() {
            return Err(SaTokenError::ConfigError(
                "request sign secret is empty".into(),
            ));
        }
        let ts = params
            .get("timestamp")
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or(SaTokenError::SignTimestampExpired)?;
        let now = chrono::Utc::now().timestamp();
        if (now - ts).abs() > self.window_secs {
            return Err(SaTokenError::SignTimestampExpired);
        }
        if let (Some(nonce), Some(dao)) = (params.get("nonce"), self.dao.as_ref()) {
            // Dedicated key space so login nonces and request-sign nonces never collide.
            // 独立键空间，避免登录 nonce 与请求签名 nonce 互相占位。
            let nkey = dao.keys().sign_nonce(nonce);
            let inserted = dao
                .set_if_absent(
                    &nkey,
                    "1",
                    Some(Duration::from_secs(self.window_secs as u64)),
                )
                .await?;
            if !inserted {
                return Err(SaTokenError::NonceAlreadyUsed);
            }
        }
        let expected = self.sign_params(params)?;
        if !ct_eq(expected.as_bytes(), provided_sign.as_bytes()) {
            return Err(SaTokenError::SignInvalid);
        }
        Ok(())
    }
}

/// Map generic sign errors onto SSO-facing variants used by existing match arms.
/// 把通用签名错误映射为 SSO 现有匹配臂使用的变体。
pub fn map_sign_err_to_sso(err: SaTokenError) -> SaTokenError {
    match err {
        SaTokenError::SignInvalid => SaTokenError::SsoSignInvalid,
        SaTokenError::SignTimestampExpired => SaTokenError::TicketExpired,
        other => other,
    }
}
