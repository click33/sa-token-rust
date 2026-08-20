// Author: 金书记
//
//! Token → login_id mapping markers.
//! Token → login_id 映射标记。

/// 被踢下线标记
pub const TOKEN_MAP_KICK_OUT: &str = "-5";

/// 被顶下线标记
pub const TOKEN_MAP_BE_REPLACED: &str = "-4";

/// Whether the mapping value is the kick-out marker (`-5`).
/// 映射值是否为踢下线标记（`-5`）。
pub fn is_kick_out_marker(value: &str) -> bool {
    value == TOKEN_MAP_KICK_OUT
}

/// Whether the mapping value is the replaced marker (`-4`).
/// 映射值是否为顶下线标记（`-4`）。
pub fn is_replaced_marker(value: &str) -> bool {
    value == TOKEN_MAP_BE_REPLACED
}
