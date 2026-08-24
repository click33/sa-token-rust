// Author: 金书记 | Author: Jin Shuji
//! Re-export request signing so existing `sso::sign` paths keep compiling.
//! 再导出请求签名，保持原有 `sso::sign` 路径可编译。

pub use crate::sign::{RequestSign, map_sign_err_to_sso};
