// Author: 金书记 | Author: Jin Shuji
//! SLO callback notifier.
//! SLO 回调通知器。

use async_trait::async_trait;

use crate::error::SaTokenResult;

/// Notifies client apps on single logout.
/// 单点登出时通知客户端应用。
#[async_trait]
pub trait SloNotifier: Send + Sync {
    /// Notify one client logout URL.
    /// 通知单个客户端登出 URL。
    async fn notify_logout(&self, logout_url: &str, login_id: &str) -> SaTokenResult<()>;
}

/// Default: do not call the network.
/// 默认：不发起网络请求。
pub struct NoopSloNotifier;

#[async_trait]
impl SloNotifier for NoopSloNotifier {
    async fn notify_logout(&self, _logout_url: &str, _login_id: &str) -> SaTokenResult<()> {
        Ok(())
    }
}

impl std::fmt::Debug for NoopSloNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoopSloNotifier { .. }")
    }
}

/// HTTP POST form notifier (compiled only with `sso-http`).
/// HTTP POST 表单通知器（仅 `sso-http` 时编译）。
#[cfg(feature = "sso-http")]
pub struct HttpSloNotifier {
    client: reqwest::Client,
}

#[cfg(feature = "sso-http")]
impl HttpSloNotifier {
    /// Create with a default HTTP client.
    /// 使用默认 HTTP 客户端创建。
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "sso-http")]
impl Default for HttpSloNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "sso-http")]
#[async_trait]
impl SloNotifier for HttpSloNotifier {
    async fn notify_logout(&self, logout_url: &str, login_id: &str) -> SaTokenResult<()> {
        let resp = self
            .client
            .post(logout_url)
            .form(&[("loginId", login_id)])
            .send()
            .await
            .map_err(|e| {
                crate::error::SaTokenError::StorageError(format!("SLO notify failed: {e}"))
            })?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(crate::error::SaTokenError::StorageError(format!(
                "SLO notify HTTP {}",
                resp.status()
            )))
        }
    }
}
