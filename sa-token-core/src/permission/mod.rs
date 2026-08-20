// Author: 金书记 | Author: Jin Shuji
//
//! Permission Matching | 权限匹配
//!
//! 本模块只负责「**匹配策略**」，不负责「**数据来源**」：
//! 权限/角色数据统一由 [`crate::stp_interface::StpInterface`] 提供，
//! 校验入口统一是 [`crate::service::AuthzService`]。
//!
//! This module owns the **matching strategy** only, never the **data source**:
//! permission/role data comes from `StpInterface`, and all checks funnel through
//! `AuthzService`.
//!
//! ## 历史变更 | History
//!
//! `PermissionChecker` / `RoleChecker` 曾定义于此，但全仓库无任何实现，
//! 且签名缺少 `login_type` 参数、无法支持多账号体系，已于 B2 删除。
//! 自定义权限数据源请实现 [`crate::stp_interface::StpInterface`]。
//!
//! `PermissionChecker` / `RoleChecker` used to live here. They had zero
//! implementations repository-wide and their signatures lacked `login_type`,
//! making multi-account systems impossible. Removed in B2 — implement
//! `StpInterface` instead.

pub mod matcher;

pub use matcher::{AntPermissionMatcher, ExactMatcher, PermissionMatcher};
