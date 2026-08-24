//! 服务层：跨仓储的业务编排与事务补偿。
//!
//! Service layer: cross-repository orchestration and compensation.
//!
//! - [`auth_service`]：登录 / 登出 / 踢人 / 续期的编排与补偿（B1）
//! - [`authz_service`]：权限与角色的读写、校验、封禁回落唯一入口（B2）
//! - [`grant_cache`]：授权数据的分片 TTL 缓存（B2，默认关闭）
//! - [`compensate`]：登录事务的反向回滚步骤（B1）
//! - [`login_request`]：登录参数对象（B1）

pub mod auth_service;
pub mod authz_service;
pub mod compensate;
pub mod grant_cache;
pub mod login_request;

pub use auth_service::AuthService;
pub use authz_service::AuthzService;
pub use compensate::{LoginCompensator, RollbackReport};
pub use grant_cache::{GrantCache, GrantKind};
pub use login_request::LoginRequest;
