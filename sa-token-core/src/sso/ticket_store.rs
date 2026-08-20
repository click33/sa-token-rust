// Author: 金书记 | Author: Jin Shuji
//! SSO ticket persistence via SaTokenDao.
//! 经 SaTokenDao 持久化 SSO 票据。

use std::sync::Arc;
use std::time::Duration;

use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use crate::sso::SsoTicket;

/// Ticket store backed by Dao TTL keys.
/// 基于 Dao TTL 键的票据存储。
pub struct SsoTicketStore {
    dao: Arc<SaTokenDao>,
    ticket_ttl_secs: i64,
}

impl std::fmt::Debug for SsoTicketStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SsoTicketStore { .. }")
    }
}

impl SsoTicketStore {
    /// Create a store with the given ticket TTL (seconds).
    /// 使用给定票据 TTL（秒）创建存储。
    pub fn new(dao: Arc<SaTokenDao>, ticket_ttl_secs: i64) -> Self {
        Self {
            dao,
            ticket_ttl_secs,
        }
    }

    fn ttl(&self) -> Option<Duration> {
        if self.ticket_ttl_secs > 0 {
            Some(Duration::from_secs(self.ticket_ttl_secs as u64))
        } else {
            None
        }
    }

    /// Persist a ticket.
    /// 持久化票据。
    pub async fn save(&self, ticket: &SsoTicket) -> SaTokenResult<()> {
        let key = self.dao.keys().sso_ticket(&ticket.ticket_id);
        self.dao.set_object(&key, ticket, self.ttl()).await
    }

    /// Load a ticket without consuming it.
    /// 加载票据但不消费。
    pub async fn get(&self, ticket_id: &str) -> SaTokenResult<Option<SsoTicket>> {
        let key = self.dao.keys().sso_ticket(ticket_id);
        self.dao.get_object(&key).await
    }

    /// Atomically consume: take_string then decode. No rewrite on failure.
    /// 原子消费：take_string 后解码。失败不回写。
    pub async fn consume(&self, ticket_id: &str, service: &str) -> SaTokenResult<String> {
        let key = self.dao.keys().sso_ticket(ticket_id);
        let raw = self
            .dao
            .take_string(&key)
            .await?
            .ok_or(SaTokenError::InvalidTicket)?;
        let ticket: SsoTicket = self.dao.decode(&raw)?;
        if !ticket.is_valid() {
            return Err(SaTokenError::TicketExpired);
        }
        if ticket.service != service {
            return Err(SaTokenError::ServiceMismatch);
        }
        Ok(ticket.login_id)
    }

    /// Non-consuming check returning login_id and remaining seconds.
    /// 非消费校验，返回 login_id 与剩余秒数。
    pub async fn check(&self, ticket_id: &str, service: &str) -> SaTokenResult<(String, i64)> {
        let ticket = self
            .get(ticket_id)
            .await?
            .ok_or(SaTokenError::InvalidTicket)?;
        if !ticket.is_valid() {
            return Err(SaTokenError::TicketExpired);
        }
        if ticket.service != service {
            return Err(SaTokenError::ServiceMismatch);
        }
        let remain = ticket.expire_time.signed_duration_since(chrono::Utc::now());
        Ok((ticket.login_id, remain.num_seconds().max(0)))
    }
}
