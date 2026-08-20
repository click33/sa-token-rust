// Author: 金书记 | Author: Jin Shuji
//! Optional background cleanup for backends without TTL.
//! 无 TTL 后端的可选后台清理。

mod background;
pub use background::{BackgroundCleanupTask, CleanupConfig};
