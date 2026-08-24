// Author: 金书记 | Author: Jin Shuji
//
//! Permission / Role / Ban Data Source | 权限、角色、封禁数据源
//!
//! Application-supplied permission / role data source (DB, RPC, config, …).
//! 由业务方实现的权限/角色数据源（数据库、RPC、配置中心……）。
//! This crate adds [`StpInterface::is_writable`] to answer where write ops land.
//! 本 crate 额外提供 [`StpInterface::is_writable`]，标明写操作落点。
//!
//! The application implements it to plug a data
//! source (database, RPC, config service, ...) into the framework.
//! [`StpInterface::is_writable`] answers: **where should framework-issued writes land?**
//!
//! ## 唯一数据源 | Single Data Source
//!
//! B2 起，本 trait 是权限/角色/封禁数据的**唯一**抽象：
//! - 未注入自定义实现时，框架使用 [`StorageStpInterface`]（读写都走 storage）
//! - 注入后，**读**走回调；**写**按 [`crate::config::GrantWritePolicy`] 处理
//! - 优先级判断**只存在于** [`crate::service::AuthzService`] 一处，
//!   `GrantRepo` 不再感知本 trait
//!
//! Since B2 this trait is the single abstraction for grant data. Without a
//! custom implementation the framework uses `StorageStpInterface`. With one,
//! reads go to the callback while writes follow `GrantWritePolicy`. The
//! precedence decision lives **only** in `AuthzService`; `GrantRepo` is
//! deliberately unaware of this trait to avoid recursing through
//! `StorageStpInterface`.

mod storage;

use async_trait::async_trait;

pub use storage::StorageStpInterface;

use crate::error::SaTokenResult;

/// 权限、角色、封禁数据回调 | Permission, role and ban data callback
#[async_trait]
pub trait StpInterface: Send + Sync {
    /// 返回账号在指定体系下的权限列表 | Permission list for the account in a login type
    async fn get_permission_list(
        &self,
        login_id: &str,
        login_type: &str,
    ) -> SaTokenResult<Vec<String>>;

    /// 返回账号在指定体系下的角色列表 | Role list for the account in a login type
    async fn get_role_list(&self, login_id: &str, login_type: &str) -> SaTokenResult<Vec<String>>;

    /// 返回封禁等级；`None` 表示未封禁。
    ///
    /// 仅在 storage 中**查不到**封禁记录时才会被调用，
    /// 因此实现方无需关心与 storage 的优先级。
    ///
    /// Ban level, `None` when not banned. Only consulted when storage has no ban
    /// record, so implementors need not reason about precedence.
    async fn is_disabled(&self, login_id: &str, service: &str) -> SaTokenResult<Option<i32>> {
        let _ = (login_id, service);
        Ok(None)
    }

    /// 本数据源是否接受框架发起的**写入**。
    ///
    /// 默认 `false`（只读），因为绝大多数自定义实现是「从既有权限系统读」，
    /// 把权限写回去需要额外的表结构与事务语义。返回 `false` 时，框架的
    /// `set_permissions` / `add_role` 等写操作会按
    /// [`crate::config::GrantWritePolicy`] 告警或拒绝，
    /// **避免写进一个自己永远读不到的地方**。
    ///
    /// 内置的 [`StorageStpInterface`] 返回 `true`，因为它的读写同源。
    ///
    /// Whether this data source accepts framework-issued writes. Defaults to
    /// `false` (read-only). The built-in `StorageStpInterface` returns `true`
    /// since its reads and writes share the same storage.
    fn is_writable(&self) -> bool {
        false
    }
}
