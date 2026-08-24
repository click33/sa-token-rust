// Author: 金书记 | Author: Jin Shuji
//! SSO session persistence via SaTokenDao.
//! 经 SaTokenDao 持久化 SSO 会话。

use std::sync::Arc;

use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use crate::sso::SsoSession;

/// Session store with CAS retry on client upsert.
/// 带 CAS 重试的会话存储（客户端 upsert）。
pub struct SsoSessionStore {
    dao: Arc<SaTokenDao>,
}

impl std::fmt::Debug for SsoSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SsoSessionStore { .. }")
    }
}

impl SsoSessionStore {
    /// Create a session store.
    /// 创建会话存储。
    pub fn new(dao: Arc<SaTokenDao>) -> Self {
        Self { dao }
    }

    /// Add a client URL to the session with CAS retries (max 8).
    /// 以 CAS 重试（最多 8 次）将会话加入客户端 URL。
    pub async fn upsert_client(&self, login_id: &str, service: &str) -> SaTokenResult<()> {
        let key = self.dao.keys().sso_session(login_id);
        for _ in 0..8 {
            let current = self.dao.get_string(&key).await?;
            let mut session = match &current {
                Some(raw) => self.dao.decode::<SsoSession>(raw)?,
                None => SsoSession::new(login_id.to_string()),
            };
            session.add_client(service.to_string());
            let new_raw = self.dao.encode(&session)?;
            let ok = self
                .dao
                .cas(&key, current.as_deref(), &new_raw, None)
                .await?;
            if ok {
                return Ok(());
            }
        }
        Err(SaTokenError::InternalError(
            "SSO session CAS retries exhausted".into(),
        ))
    }

    /// Remove session and return tracked client URLs.
    /// 删除会话并返回已跟踪的客户端 URL。
    pub async fn remove(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        let key = self.dao.keys().sso_session(login_id);
        let session = self.dao.get_object::<SsoSession>(&key).await?;
        let clients = session.map(|s| s.clients).unwrap_or_default();
        self.dao.delete(&key).await?;
        Ok(clients)
    }

    /// Load session if present.
    /// 若存在则加载会话。
    pub async fn get(&self, login_id: &str) -> SaTokenResult<Option<SsoSession>> {
        let key = self.dao.keys().sso_session(login_id);
        self.dao.get_object(&key).await
    }
}
