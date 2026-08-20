// Author: 金书记 | Author: Jin Shuji
//
//! Framework plugin trait for lifecycle hooks
//! 框架插件 trait，用于生命周期钩子
//!
//! 替代已删除的 `FrameworkAdapter`：后续 plan 将在 `sa-token-plugin-common` 统一注册。
//!
//! Replaces the deleted `FrameworkAdapter`; a future plan will register all plugins uniformly.

use async_trait::async_trait;

/// sa-token 框架插件：在应用启动/关闭时执行一次性钩子
///
/// Framework plugin for sa-token: executes one-time hooks at app startup/shutdown.
///
/// # Example
///
/// ```rust,ignore
/// use sa_token_adapter::SaTokenPlugin;
/// use async_trait::async_trait;
///
/// struct MyPlugin;
///
/// #[async_trait]
/// impl SaTokenPlugin for MyPlugin {
///     fn name(&self) -> &str { "my-plugin" }
///
///     async fn on_init(&self) -> Result<(), String> {
///         println!("Plugin '{}' initialized", self.name());
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait SaTokenPlugin: Send + Sync {
    /// 插件名称（日志与诊断用）
    ///
    /// Plugin name (for logs and diagnostics).
    fn name(&self) -> &str;

    /// 应用启动、Manager 就绪后调用
    ///
    /// Called at app startup after Manager is ready.
    async fn on_init(&self) -> Result<(), String> {
        Ok(())
    }

    /// 应用关闭、资源回收前调用
    ///
    /// Called at app shutdown before resource cleanup.
    async fn on_shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}
