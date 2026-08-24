// Author: 金书记 | Author: Jin Shuji
//! Ticket consumption backends (local Dao or signed HTTP).
//! 票据消费后端（本地 Dao 或带签名的 HTTP）。

use async_trait::async_trait;

use crate::error::SaTokenResult;
use crate::sso::ticket_store::SsoTicketStore;

/// Consumes an SSO ticket and returns login_id.
/// 消费 SSO 票据并返回 login_id。
#[async_trait]
pub trait TicketChecker: Send + Sync {
    /// Check and consume a ticket for the given service.
    /// 为给定服务校验并消费票据。
    async fn check_and_consume(&self, ticket_id: &str, service: &str) -> SaTokenResult<String>;
}

/// Same storage as the SSO server (recommended in one cluster).
/// 与 SSO 服务端共享存储（同集群推荐）。
pub struct LocalTicketChecker {
    /// Shared ticket store.
    /// 共享票据存储。
    pub store: SsoTicketStore,
}

impl std::fmt::Debug for LocalTicketChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalTicketChecker { .. }")
    }
}

#[async_trait]
impl TicketChecker for LocalTicketChecker {
    async fn check_and_consume(&self, ticket_id: &str, service: &str) -> SaTokenResult<String> {
        self.store.consume(ticket_id, service).await
    }
}

#[cfg(feature = "sso-http")]
use std::collections::BTreeMap;

#[cfg(feature = "sso-http")]
use serde::Deserialize;
#[cfg(feature = "sso-http")]
use uuid::Uuid;

#[cfg(feature = "sso-http")]
use crate::error::SaTokenError;
#[cfg(feature = "sso-http")]
use crate::sso::sign::RequestSign;

/// Signed HTTP remote ticket checker (compiled only with `sso-http`).
/// 带签名的远程 HTTP 验票器（仅 `sso-http` 时编译）。
#[cfg(feature = "sso-http")]
pub struct HttpTicketChecker {
    /// Remote check endpoint URL.
    /// 远程验票端点 URL。
    pub check_url: String,
    /// Shared request signer.
    /// 共享请求签名器。
    pub sign: RequestSign,
    /// Expected service URL.
    /// 期望的服务 URL。
    pub service: String,
    client: reqwest::Client,
}

#[cfg(feature = "sso-http")]
impl HttpTicketChecker {
    /// Create a remote checker.
    /// 创建远程验票器。
    pub fn new(
        check_url: impl Into<String>,
        sign: RequestSign,
        service: impl Into<String>,
    ) -> Self {
        Self {
            check_url: check_url.into(),
            sign,
            service: service.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "sso-http")]
#[derive(Deserialize)]
struct CheckTicketHttpBody {
    login_id: String,
    timestamp: String,
    nonce: String,
    sign: String,
}

#[cfg(feature = "sso-http")]
#[async_trait]
impl TicketChecker for HttpTicketChecker {
    async fn check_and_consume(&self, ticket_id: &str, service: &str) -> SaTokenResult<String> {
        if service != self.service {
            return Err(SaTokenError::ServiceMismatch);
        }
        let mut params = BTreeMap::new();
        params.insert("ticket".into(), ticket_id.to_string());
        params.insert("service".into(), service.to_string());
        params.insert(
            "timestamp".into(),
            chrono::Utc::now().timestamp().to_string(),
        );
        params.insert("nonce".into(), Uuid::new_v4().simple().to_string());
        let sign = self.sign.sign_params(&params)?;
        params.insert("sign".into(), sign);
        let qs: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let url = format!("{}?{}", self.check_url, qs);
        let body = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .text()
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        let parsed: CheckTicketHttpBody =
            serde_json::from_str(&body).map_err(|_| SaTokenError::InvalidTicket)?;
        let mut verify = BTreeMap::new();
        verify.insert("login_id".into(), parsed.login_id.clone());
        verify.insert("timestamp".into(), parsed.timestamp.clone());
        verify.insert("nonce".into(), parsed.nonce.clone());
        self.sign
            .verify_params(&verify, &parsed.sign)
            .await
            .map_err(crate::sso::sign::map_sign_err_to_sso)?;
        Ok(parsed.login_id)
    }
}
