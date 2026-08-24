//! 仓储层：按数据域划分的存储读写封装。
//!
//! 三个仓储各自负责一个数据域，互不直接调用（跨域协作由 service 层编排）：
//! - [`TokenRepo`]   token 体、双向映射、多设备索引、续签
//! - [`SessionRepo`] Account-Session、Token-Session、终端列表
//! - [`GrantRepo`]   权限 / 角色列表
//!
//! Repository layer: one repository per data domain. Repositories never call
//! each other; cross-domain orchestration belongs to the service layer.

pub mod grant_repo;
pub mod session_repo;
pub mod token_repo;

pub use grant_repo::GrantRepo;
pub use session_repo::SessionRepo;
pub use token_repo::{TokenIdMapping, TokenRepo};
