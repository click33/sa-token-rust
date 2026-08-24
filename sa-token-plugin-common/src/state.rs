// Author: 金书记
//
//! Framework-agnostic application state wrapping `Arc<SaTokenManager>`.
//!
//! Replaces the 5+ duplicate `SaTokenState` definitions previously scattered
//! across `actix-web-core`, `gotham-core`, `salvo-core`, `rocket-core`, and `ntex-core`.

use std::sync::Arc;

use sa_token_adapter::serializer::SharedSerializer;
use sa_token_adapter::storage::SaStorage;
use sa_token_core::config::TokenStyle;
use sa_token_core::event::{SaTokenEventBus, SaTokenListener};
use sa_token_core::keys::SaKeyLayout;
use sa_token_core::{SaTokenConfig, SaTokenManager};

/// Shared application state for all framework plugins.
///
/// In Actix wrap with `web::Data`, in Axum just `Clone`.
#[derive(Clone)]
pub struct SaTokenState {
    /// Thread-safe shared authentication manager.
    pub manager: Arc<SaTokenManager>,
}

impl std::fmt::Debug for SaTokenState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SaTokenState")
            .field("manager", &self.manager)
            .finish()
    }
}

impl SaTokenState {
    /// Build from a storage backend and a complete config.
    pub fn new(storage: Arc<dyn SaStorage>, config: SaTokenConfig) -> Self {
        Self {
            manager: Arc::new(SaTokenManager::new(storage, config)),
        }
    }

    /// Build from an existing manager (useful for tests or multi-plugin sharing).
    pub fn from_manager(manager: SaTokenManager) -> Self {
        Self {
            manager: Arc::new(manager),
        }
    }

    /// Fluent builder entry.
    pub fn builder() -> SaTokenStateBuilder {
        SaTokenStateBuilder::default()
    }
}

/// Fluent builder for [`SaTokenState`], forwarding every real
/// [`SaTokenConfigBuilder`](sa_token_core::config::SaTokenConfigBuilder) method.
#[derive(Default)]
pub struct SaTokenStateBuilder {
    config_builder: sa_token_core::config::SaTokenConfigBuilder,
}

impl std::fmt::Debug for SaTokenStateBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SaTokenStateBuilder { .. }")
    }
}

impl SaTokenStateBuilder {
    // ── storage (required) ──────────────────────────────────────────

    /// Set the storage implementation (required).
    pub fn storage(mut self, storage: Arc<dyn SaStorage>) -> Self {
        self.config_builder = self.config_builder.storage(storage);
        self
    }

    // ── token identity ──────────────────────────────────────────────

    /// Token name used in header / cookie / query (default `"sa-token"`).
    pub fn token_name(mut self, name: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.token_name(name);
        self
    }

    /// Token generation style (default `Uuid`).
    pub fn token_style(mut self, style: TokenStyle) -> Self {
        self.config_builder = self.config_builder.token_style(style);
        self
    }

    // ── timeout ─────────────────────────────────────────────────────

    /// Token lifetime in seconds; `-1` = permanent (default 30 days).
    pub fn timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.timeout(timeout);
        self
    }

    /// Activity interval in seconds; `-1` disables (default `-1`).
    pub fn active_timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.active_timeout(timeout);
        self
    }

    /// Per-token dynamic `active_timeout` (default `false`).
    pub fn dynamic_active_timeout(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.dynamic_active_timeout(enabled);
        self
    }

    /// Auto-renewal on read (default `false` since 0.2.0).
    pub fn auto_renew(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.auto_renew(enabled);
        self
    }

    /// Renewal threshold in seconds (default `300`).
    pub fn renew_threshold(mut self, seconds: i64) -> Self {
        self.config_builder = self.config_builder.renew_threshold(seconds);
        self
    }

    // ── concurrency ─────────────────────────────────────────────────

    /// Allow concurrent logins per account (default `true`).
    pub fn is_concurrent(mut self, concurrent: bool) -> Self {
        self.config_builder = self.config_builder.is_concurrent(concurrent);
        self
    }

    /// Share one token across concurrent sessions (default `false`).
    pub fn is_share(mut self, share: bool) -> Self {
        self.config_builder = self.config_builder.is_share(share);
        self
    }

    /// Emit operation logs at info level when true.
    pub fn is_log(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.is_log(enabled);
        self
    }

    /// Read token from headers (including Authorization fallback).
    pub fn is_read_header(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.is_read_header(enabled);
        self
    }

    /// Read token from cookies.
    pub fn is_read_cookie(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.is_read_cookie(enabled);
        self
    }

    /// Read token from query/param.
    pub fn is_read_body(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.is_read_body(enabled);
        self
    }

    /// Custom token prefix.
    pub fn token_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.token_prefix(prefix);
        self
    }

    /// Opt-in cookie write (default false).
    pub fn is_write_cookie(mut self, write: bool) -> Self {
        self.config_builder = self.config_builder.is_write_cookie(write);
        self
    }

    /// Cookie Domain attribute.
    pub fn cookie_domain(mut self, domain: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.cookie_domain(domain);
        self
    }

    /// Cookie Path attribute.
    pub fn cookie_path(mut self, path: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.cookie_path(path);
        self
    }

    /// Cookie HttpOnly flag.
    pub fn cookie_http_only(mut self, http_only: bool) -> Self {
        self.config_builder = self.config_builder.cookie_http_only(http_only);
        self
    }

    /// Cookie Secure flag.
    pub fn cookie_secure(mut self, secure: bool) -> Self {
        self.config_builder = self.config_builder.cookie_secure(secure);
        self
    }

    /// Cookie SameSite attribute.
    pub fn cookie_same_site(mut self, same_site: sa_token_adapter::context::SameSite) -> Self {
        self.config_builder = self.config_builder.cookie_same_site(same_site);
        self
    }

    /// Max concurrent logins; `-1` = unlimited (default `-1`).
    pub fn max_login_count(mut self, count: i64) -> Self {
        self.config_builder = self.config_builder.max_login_count(count);
        self
    }

    /// Overflow logout mode.
    pub fn overflow_logout_mode(mut self, mode: sa_token_core::config::LogoutMode) -> Self {
        self.config_builder = self.config_builder.overflow_logout_mode(mode);
        self
    }

    /// Non-concurrent replace exit mode.
    pub fn replaced_login_exit_mode(
        mut self,
        mode: sa_token_core::config::ReplacedLoginExitMode,
    ) -> Self {
        self.config_builder = self.config_builder.replaced_login_exit_mode(mode);
        self
    }

    /// Replace scope (current device type or all).
    pub fn replaced_range(mut self, range: sa_token_core::config::ReplacedRange) -> Self {
        self.config_builder = self.config_builder.replaced_range(range);
        self
    }

    // ── storage keys ────────────────────────────────────────────────

    /// Storage key prefix (default `"sa:"`).
    pub fn storage_key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.storage_key_prefix(prefix);
        self
    }

    /// Storage key layout strategy.
    pub fn key_layout(mut self, layout: SaKeyLayout) -> Self {
        self.config_builder = self.config_builder.key_layout(layout);
        self
    }

    // ── JWT ──────────────────────────────────────────────────────────

    /// JWT secret key (required for `TokenStyle::Jwt`).
    pub fn jwt_secret_key(mut self, key: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.jwt_secret_key(key);
        self
    }

    /// JWT algorithm (default `"HS256"`).
    pub fn jwt_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.jwt_algorithm(algorithm);
        self
    }

    /// JWT issuer (`iss` claim).
    pub fn jwt_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.jwt_issuer(issuer);
        self
    }

    /// JWT audience (`aud` claim).
    pub fn jwt_audience(mut self, audience: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.jwt_audience(audience);
        self
    }

    /// Fall back to UUID when JWT generation fails (default `false`).
    pub fn jwt_fallback_on_error(mut self, fallback: bool) -> Self {
        self.config_builder = self.config_builder.jwt_fallback_on_error(fallback);
        self
    }

    // ── nonce / refresh ─────────────────────────────────────────────

    /// Enable anti-replay nonce (default `false`).
    pub fn enable_nonce(mut self, enable: bool) -> Self {
        self.config_builder = self.config_builder.enable_nonce(enable);
        self
    }

    /// Nonce lifetime in seconds; `-1` follows token timeout.
    pub fn nonce_timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.nonce_timeout(timeout);
        self
    }

    /// Enable refresh tokens (default `false`).
    pub fn enable_refresh_token(mut self, enable: bool) -> Self {
        self.config_builder = self.config_builder.enable_refresh_token(enable);
        self
    }

    /// Refresh token lifetime in seconds (default 7 days).
    pub fn refresh_token_timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.refresh_token_timeout(timeout);
        self
    }

    // ── session behaviour ───────────────────────────────────────────

    /// Create Token-Session immediately on login (default `false`).
    pub fn right_now_create_token_session(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.right_now_create_token_session(enabled);
        self
    }

    /// Require valid login when fetching Token-Session (default `true`).
    pub fn token_session_check_login(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.token_session_check_login(enabled);
        self
    }

    /// Default logout range.
    pub fn logout_range(mut self, range: sa_token_core::config::LogoutRange) -> Self {
        self.config_builder = self.config_builder.logout_range(range);
        self
    }

    /// Keep Token-Session on logout (default `false`).
    pub fn is_logout_keep_token_session(mut self, keep: bool) -> Self {
        self.config_builder = self.config_builder.is_logout_keep_token_session(keep);
        self
    }

    // ── grant cache (B2) ────────────────────────────────────────────

    /// Permission/role cache TTL in seconds; `<= 0` disables (default `0`).
    pub fn grant_cache_ttl(mut self, seconds: i64) -> Self {
        self.config_builder = self.config_builder.grant_cache_ttl(seconds);
        self
    }

    /// Total cache capacity across all shards.
    pub fn grant_cache_max_entries(mut self, max: usize) -> Self {
        self.config_builder = self.config_builder.grant_cache_max_entries(max);
        self
    }

    /// Toggle single-flight for concurrent cache misses.
    pub fn grant_cache_single_flight(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.grant_cache_single_flight(enabled);
        self
    }

    /// Toggle per-request authorization snapshot.
    pub fn grant_request_scope(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.grant_request_scope(enabled);
        self
    }

    /// Write policy for read-only `StpInterface`.
    pub fn grant_write_policy(mut self, policy: sa_token_core::config::GrantWritePolicy) -> Self {
        self.config_builder = self.config_builder.grant_write_policy(policy);
        self
    }

    /// Enable wildcard matching for roles (default `false`, exact match).
    pub fn role_wildcard(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.role_wildcard(enabled);
        self
    }

    // ── context ─────────────────────────────────────────────────────

    /// Auto-create empty context in `with_current_mut` (default `false`).
    pub fn context_auto_create(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.context_auto_create(enabled);
        self
    }

    /// Max attempts when allocating a unique login / temp token (`-1` = no retry).
    pub fn max_try_times(mut self, n: i32) -> Self {
        self.config_builder = self.config_builder.max_try_times(n);
        self
    }

    /// HMAC secret for `RequestSign` via StpUtil (independent from JWT).
    pub fn sign_secret_key(mut self, key: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.sign_secret_key(key);
        self
    }

    /// Timestamp window in seconds for `RequestSign`.
    pub fn sign_window_secs(mut self, secs: i64) -> Self {
        self.config_builder = self.config_builder.sign_window_secs(secs);
        self
    }

    // ── serializer / events ─────────────────────────────────────────

    /// Override the storage serializer (default JSON).
    pub fn serializer(mut self, serializer: SharedSerializer) -> Self {
        self.config_builder = self.config_builder.serializer(serializer);
        self
    }

    /// Inject a shared event bus.
    pub fn event_bus(mut self, bus: SaTokenEventBus) -> Self {
        self.config_builder = self.config_builder.event_bus(bus);
        self
    }

    /// Register an event listener (may be called multiple times).
    pub fn register_listener(mut self, listener: Arc<dyn SaTokenListener>) -> Self {
        self.config_builder = self.config_builder.register_listener(listener);
        self
    }

    // ── build ───────────────────────────────────────────────────────

    /// Build `SaTokenState`. Panics if `storage` was not set.
    pub fn build(self) -> SaTokenState {
        let manager = self.config_builder.build();
        SaTokenState {
            manager: Arc::new(manager),
        }
    }
}
