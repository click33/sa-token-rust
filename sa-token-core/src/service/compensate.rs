//! 登录阶段写入的逆序补偿器。
//!
//! 登录是一个跨多个存储键的复合操作（索引、终端、token 体、反向映射、
//! refresh token、提交点映射）。底层 `SaStorage` 只提供单键原子性（A1 未引入
//! 多键事务），因此这里用「记录 + 逆序补偿」在应用层近似事务语义：
//! 每完成一步就登记它的逆操作，任一步失败即按**完成顺序的逆序**撤销，
//! 使存储不残留半成品数据。
//!
//! 补偿是 best-effort：极端存储故障下仍可能残留孤儿键，此时通过
//! [`RollbackReport`] 上报，由日志与后台清理任务兜底。
//!
//! Reverse-order compensator for the staged login writes.
//!
//! A login touches several storage keys, and the `SaStorage` contract only
//! guarantees single-key atomicity, so transactional semantics are approximated
//! at the application level: every completed step registers its inverse, and a
//! failure undoes them in reverse completion order. Compensation is best-effort;
//! leftovers are surfaced through [`RollbackReport`].

use std::time::Duration;

use crate::dao::SaTokenDao;

/// 单条回滚动作 | A single rollback action
enum RollbackStep {
    /// 删除已写入的键 | Delete a key that was just written
    DeleteKey { key: String },
    /// 恢复被覆盖的旧值（如 Account-Session 被追加终端前的快照）
    /// Restore a previous value that got overwritten
    RestoreKey {
        key: String,
        value: String,
        ttl: Option<Duration>,
    },
    /// 从列表移除成员（索引回滚的正确姿势，修 B1-8）
    /// Remove a member from a list — the correct way to roll back an index push
    ListRemove { key: String, member: String },
}

impl RollbackStep {
    /// 用于日志与报告的键名 | Key name used in logs and reports
    fn key(&self) -> &str {
        match self {
            RollbackStep::DeleteKey { key }
            | RollbackStep::RestoreKey { key, .. }
            | RollbackStep::ListRemove { key, .. } => key,
        }
    }
}

/// 回滚结果报告 | Outcome report of a rollback
#[derive(Debug, Default)]
pub struct RollbackReport {
    /// 成功撤销的步骤数 | Number of successfully reverted steps
    pub succeeded: usize,
    /// 撤销失败的 (键, 错误描述) | Failed steps as (key, error message)
    pub failed: Vec<(String, String)>,
}

impl RollbackReport {
    /// 是否完全干净（无残留）| Whether the rollback left nothing behind
    pub fn is_clean(&self) -> bool {
        self.failed.is_empty()
    }

    /// 残留键清单，供上层告警或后台清理任务消费
    /// Orphan keys, for alerting or a background sweeper
    pub fn orphan_keys(&self) -> Vec<&str> {
        self.failed.iter().map(|(k, _)| k.as_str()).collect()
    }
}

/// 阶段写入补偿器：记录已完成步骤，失败时逆序回滚。
/// Staged-write compensator: records completed steps and reverts them in reverse.
pub struct LoginCompensator {
    steps: Vec<RollbackStep>,
}

impl std::fmt::Debug for LoginCompensator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginCompensator { .. }")
    }
}

impl LoginCompensator {
    /// 创建空补偿器。成功路径上除一次 `Vec::new()`（不分配）外零开销。
    /// Create an empty compensator; zero-cost on the success path.
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// 登记「失败时删除该键」| Register "delete this key on failure"
    pub fn on_fail_delete(&mut self, key: impl Into<String>) {
        self.steps.push(RollbackStep::DeleteKey { key: key.into() });
    }

    /// 登记「失败时恢复旧值」。
    ///
    /// `ttl` 应传入**剩余寿命**而非原始 TTL，否则恢复后寿命会被意外延长。
    /// Register "restore the previous value on failure". Pass the *remaining*
    /// lifetime as `ttl`, otherwise the restored key would outlive the original.
    pub fn on_fail_restore(
        &mut self,
        key: impl Into<String>,
        old_value: impl Into<String>,
        ttl: Option<Duration>,
    ) {
        self.steps.push(RollbackStep::RestoreKey {
            key: key.into(),
            value: old_value.into(),
            ttl,
        });
    }

    /// 登记「失败时从列表移除成员」（索引回滚，修 B1-8）
    /// Register "remove this member from the list on failure".
    pub fn on_fail_list_remove(&mut self, key: impl Into<String>, member: impl Into<String>) {
        self.steps.push(RollbackStep::ListRemove {
            key: key.into(),
            member: member.into(),
        });
    }

    /// 已登记的步骤数（诊断用）| Number of registered steps (diagnostics)
    pub fn pending(&self) -> usize {
        self.steps.len()
    }

    /// 登录成功：丢弃全部补偿记录，消费 self 防止误用。
    /// Commit: drop all registered steps, consuming `self` to prevent misuse.
    pub fn commit(self) {
        drop(self);
    }

    /// 登录失败：逆序执行全部回滚。
    ///
    /// best-effort 语义：单步失败**不阻断**后续步骤，全部尝试完毕后统一上报，
    /// 因为「少撤销一个键」远好于「因第一个键失败而放弃撤销其余五个键」。
    ///
    /// Roll back every registered step in reverse order. Best-effort: a failing
    /// step never aborts the remaining ones, since leaving one key behind is far
    /// better than abandoning the rest of the cleanup.
    pub async fn rollback(&self, dao: &SaTokenDao) -> RollbackReport {
        let mut report = RollbackReport::default();

        for step in self.steps.iter().rev() {
            let outcome = match step {
                RollbackStep::DeleteKey { key } => dao.delete(key).await.map(|_| ()),
                RollbackStep::RestoreKey { key, value, ttl } => {
                    dao.set_string(key, value, *ttl).await
                }
                RollbackStep::ListRemove { key, member } => {
                    dao.list_remove(key, member).await.map(|_| ())
                }
            };

            match outcome {
                Ok(()) => report.succeeded += 1,
                Err(e) => report.failed.push((step.key().to_string(), e.to_string())),
            }
        }

        // 残留键必须可观测，否则运维无从发现存储脏数据（修 B1-17）
        // Orphan keys must be observable, otherwise dirty state goes unnoticed.
        if !report.is_clean() {
            tracing::error!(
                succeeded = report.succeeded,
                failed = report.failed.len(),
                orphans = ?report.orphan_keys(),
                "login rollback incomplete, orphan keys left in storage"
            );
        } else if report.succeeded > 0 {
            tracing::warn!(
                reverted = report.succeeded,
                "login failed, all staged writes reverted"
            );
        }

        report
    }
}

impl Default for LoginCompensator {
    fn default() -> Self {
        Self::new()
    }
}
