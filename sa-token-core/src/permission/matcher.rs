// Author: 金书记 | Author: Jin Shuji
//
//! Wildcard matcher for permission strings (`*` / `?` / segment `*`). Roles default to exact match.
//! 权限字符串通配匹配；角色默认精确匹配。
//!
//! ## Wildcard Semantics | 通配符语义
//!
//! | Pattern | Matches | Does NOT match |
//! |---------|---------|----------------|
//! | `user:read` | `user:read` | anything else |
//! | `*` / `**` | everything | — |
//! | `user:*` | `user:add` | `user`, `user:add:vip` |
//! | `user:**` | `user`, `user:add`, `user:add:vip` | `userx`, `other` |
//! | `user:*:read` | `user:add:read` | `user:read`, `user:a:b:read` |
//!
//! ## Performance | 性能
//!
//! - 无通配符的模式走 `memchr` 短路，不进入分段循环
//!   Patterns without `*` short-circuit via `memchr`, skipping the segment loop.
//! - 分段比较使用 `str::split` 惰性迭代器，**零堆分配**
//!   Segment comparison uses the lazy `str::split` iterator: zero allocations.

use std::collections::HashSet;
use std::fmt::Debug;

/// 段分隔符：与权限串书写习惯 `user:add` 保持一致。
/// Segment separator, matching the conventional `user:add` notation.
const SEGMENT_SEP: char = ':';

/// 单段通配符：匹配恰好一个段。
/// Single-segment wildcard: matches exactly one segment.
const WILDCARD_ONE: &str = "*";

/// 多段通配符：匹配剩余任意数量的段（含零段）。
/// Multi-segment wildcard: matches any number of remaining segments, including none.
const WILDCARD_MANY: &str = "**";

/// 权限/角色匹配策略 | Permission / role matching strategy
///
/// 实现方只需提供 [`matches_one`](PermissionMatcher::matches_one)，
/// 列表级与批量级方法都有合理默认实现。
///
/// Implementors only need `matches_one`; the list-level and bulk-level methods
/// come with sensible defaults.
pub trait PermissionMatcher: Send + Sync + Debug {
    /// 判断**单个**已持有的模式 `owned` 是否覆盖待校验项 `required`。
    /// Whether a single owned pattern covers the required item.
    fn matches_one(&self, owned: &str, required: &str) -> bool;

    /// 已持有列表中是否存在一项覆盖 `required`。
    ///
    /// `required` 为空串一律返回 `false`：空权限名没有业务含义。
    ///
    /// Whether any owned entry covers `required`. An empty `required` always
    /// returns `false`.
    fn matches(&self, owned: &[String], required: &str) -> bool {
        if required.is_empty() {
            return false;
        }
        owned.iter().any(|p| self.matches_one(p, required))
    }

    /// AND 语义：`required` 每一项都必须被覆盖。
    ///
    /// 空 `required` 返回 `true`（「没有任何要求」自然满足）。
    ///
    /// AND semantics: every entry in `required` must be covered. An empty
    /// `required` yields `true`.
    fn matches_all(&self, owned: &[String], required: &[&str]) -> bool {
        required.iter().all(|r| self.matches(owned, r))
    }

    /// OR 语义：`required` 任一项被覆盖即可。
    ///
    /// 空 `required` 返回 `false`（「一个都没满足」）。
    ///
    /// OR semantics: any single entry suffices. An empty `required` yields
    /// `false`.
    fn matches_any(&self, owned: &[String], required: &[&str]) -> bool {
        required.iter().any(|r| self.matches(owned, r))
    }
}

/// Ant 风格分段匹配器（权限默认策略）| Ant-style segment matcher (default for permissions)
#[derive(Debug, Clone, Copy, Default)]
pub struct AntPermissionMatcher;

impl AntPermissionMatcher {
    /// 分段匹配核心：`pattern` 与 `target` 同时按 `:` 切分，逐段比对。
    ///
    /// 判定顺序至关重要 —— `Some(WILDCARD_MANY)` 必须排在 `(Some(_), None)` 之前，
    /// 否则 `user:**` 匹配 `user` 时会因「pattern 还有段而 target 已耗尽」被误判。
    ///
    /// Core segment matcher: both sides are split on `:` and compared pairwise.
    fn segment_match(pattern: &str, target: &str) -> bool {
        let mut pat = pattern.split(SEGMENT_SEP);
        let mut tgt = target.split(SEGMENT_SEP);

        loop {
            match (pat.next(), tgt.next()) {
                (None, None) => return true,
                (None, Some(_)) => return false,
                (Some(WILDCARD_MANY), _) => return true,
                (Some(_), None) => return false,
                (Some(WILDCARD_ONE), Some(_)) => continue,
                (Some(p), Some(t)) => {
                    if p != t {
                        return false;
                    }
                }
            }
        }
    }
}

impl PermissionMatcher for AntPermissionMatcher {
    fn matches_one(&self, owned: &str, required: &str) -> bool {
        if owned == required {
            return true;
        }
        if owned == WILDCARD_ONE || owned == WILDCARD_MANY {
            return true;
        }
        if !owned.contains('*') {
            return false;
        }
        Self::segment_match(owned, required)
    }

    /// 批量 AND 的混合策略：精确项走 `HashSet`，通配项线性扫。
    /// Hybrid bulk-AND: exact items via `HashSet`, wildcard items via linear scan.
    fn matches_all(&self, owned: &[String], required: &[&str]) -> bool {
        if required.is_empty() {
            return true;
        }
        if required.len() == 1 {
            return required.first().is_some_and(|r| self.matches(owned, r));
        }

        let (exact, wildcard) = split_exact_and_wildcard(owned);
        required.iter().all(|r| {
            !r.is_empty() && (exact.contains(*r) || wildcard.iter().any(|w| self.matches_one(w, r)))
        })
    }

    /// 批量 OR 的混合策略。
    /// Hybrid bulk-OR strategy.
    fn matches_any(&self, owned: &[String], required: &[&str]) -> bool {
        if required.is_empty() {
            return false;
        }
        if required.len() == 1 {
            return required.first().is_some_and(|r| self.matches(owned, r));
        }

        let (exact, wildcard) = split_exact_and_wildcard(owned);
        required.iter().any(|r| {
            !r.is_empty() && (exact.contains(*r) || wildcard.iter().any(|w| self.matches_one(w, r)))
        })
    }
}

/// 把已持有列表拆分为「精确项集合」与「含通配符项列表」。
///
/// Splits an owned list into an exact-match set and a wildcard list.
fn split_exact_and_wildcard(owned: &[String]) -> (HashSet<&str>, Vec<&str>) {
    let mut exact = HashSet::with_capacity(owned.len());
    let mut wildcard = Vec::new();
    for item in owned {
        if item.contains('*') {
            wildcard.push(item.as_str());
        } else {
            exact.insert(item.as_str());
        }
    }
    (exact, wildcard)
}

/// 精确匹配器（角色默认策略）| Exact matcher (default for roles)
///
/// Roles default to exact match (this implementation).
/// 角色默认精确匹配（本实现）。
#[derive(Debug, Clone, Copy, Default)]
pub struct ExactMatcher;

impl PermissionMatcher for ExactMatcher {
    fn matches_one(&self, owned: &str, required: &str) -> bool {
        owned == required
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ant_star_vs_double_star() {
        let m = AntPermissionMatcher;
        let owned = vec!["user:*".to_string()];
        assert!(m.matches(&owned, "user:list"));
        assert!(!m.matches(&owned, "user:a:b"));
        let owned2 = vec!["user:**".to_string()];
        assert!(m.matches(&owned2, "user:a:b"));
        assert!(!m.matches(&owned2, "other:x"));
    }

    #[test]
    fn ant_empty_and_or() {
        let m = AntPermissionMatcher;
        let owned = vec!["a".to_string()];
        assert!(m.matches_all(&owned, &[]));
        assert!(!m.matches_any(&owned, &[]));
    }

    #[test]
    fn exact_matcher() {
        let m = ExactMatcher;
        assert!(m.matches_one("admin", "admin"));
        assert!(!m.matches_one("admin", "user"));
    }
}
