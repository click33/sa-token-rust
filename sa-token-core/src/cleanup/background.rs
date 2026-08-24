// Author: 金书记 | Author: Jin Shuji
//! Optional interval cleanup. Disabled by default — never auto-spawn from Manager::new.
//! 可选定时清理。默认关闭 —— 禁止在 Manager::new 里自动 spawn。

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time;

use crate::nonce::NonceManager;
use crate::online::OnlineManager;

/// Cleanup switches | 清理开关
#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// Master switch; false means spawn() returns a no-op handle.
    /// 总开关；false 时 spawn 返回空操作句柄。
    pub enabled: bool,
    /// `interval` | `interval`
    pub interval: Duration,
    /// `cleanup_nonce` | `cleanup_nonce`
    pub cleanup_nonce: bool,
    /// Best-effort prune of online indexes (list members whose record expired).
    /// 尽力修剪在线索引（记录已过期的列表成员）。
    pub cleanup_online: bool,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: Duration::from_secs(300),
            cleanup_nonce: true,
            cleanup_online: true,
        }
    }
}

/// Handle that can be asked to stop without aborting in-flight IO blindly.
/// 可协作停止的句柄，避免直接 abort 中断进行中的 IO。
pub struct BackgroundCleanupTask {
    stop: watch::Sender<bool>,
    /// Kept so the task is not detached without a way to observe join later.
    /// 保留句柄，便于后续观察 join；协作停止靠 `stop` 信号。
    #[allow(dead_code)]
    handle: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for BackgroundCleanupTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackgroundCleanupTask { .. }")
    }
}

impl BackgroundCleanupTask {
    /// `spawn` — spawn | `spawn`
    pub fn spawn(
        config: CleanupConfig,
        nonce: Option<Arc<NonceManager>>,
        online: Option<Arc<OnlineManager>>,
    ) -> Self {
        let (stop, rx) = watch::channel(false);
        if !config.enabled {
            return Self { stop, handle: None };
        }

        let handle = tokio::spawn(async move {
            let mut ticker = time::interval(config.interval);
            ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            let mut rx = rx;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if config.cleanup_nonce {
                            if let Some(n) = &nonce {
                                if let Err(e) = n.cleanup_expired().await {
                                    tracing::warn!(error = %e, "nonce cleanup failed");
                                }
                            }
                        }
                        if config.cleanup_online {
                            if let Some(o) = &online {
                                match o.get_online_users().await {
                                    Ok(users) => {
                                        for uid in users {
                                            if let Err(e) = o.get_user_sessions(&uid).await {
                                                tracing::warn!(error = %e, login_id = %uid, "online prune failed");
                                            }
                                        }
                                    }
                                    Err(e) => tracing::warn!(error = %e, "online list failed during cleanup"),
                                }
                            }
                        }
                    }
                    _ = rx.changed() => {
                        if *rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        Self {
            stop,
            handle: Some(handle),
        }
    }

    /// Cooperative stop | 协作停止
    pub fn shutdown(&self) {
        let _ = self.stop.send(true);
    }
}

impl Drop for BackgroundCleanupTask {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}
