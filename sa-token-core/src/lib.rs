// Author: 金书记
//
//! # sa-token-core
//!
//! sa-token-rust 的核心库，提供与框架无关的认证授权功能
//!
//! ## 主要功能
//!
//! - Token 管理：生成、验证、刷新
//! - Session 管理：会话存储与管理
//! - 权限验证：基于角色/权限的访问控制
//! - 账号管理：登录、登出、踢人下线、封禁等
//!
//! ## 使用示例
//!
//! ```rust,ignore
//! use sa_token_core::SaTokenManager;
//!
//! let manager = SaTokenManager::new(storage, config);
//! let token = manager.login("user_123").await?;
//! ```

pub mod cleanup;
pub mod codec;
pub mod config;
pub mod context;
pub mod dao;
pub mod disable;
pub mod distributed;
pub mod event;
pub mod http_basic;
pub mod keys;
pub mod nonce;
pub mod oauth2;
pub mod online;
pub mod permission;
/// Common re-exports | 常用类型重导出
pub mod prelude;
pub mod refresh;
pub mod repository;
/// Path-based auth routing | 基于路径的鉴权路由
pub mod router;
pub mod safe;
pub mod same_token;
pub mod service;
pub mod session;
pub mod sign;
pub mod sso;
pub mod stp_interface;
pub mod stp_logic;
pub mod temp_token;
pub mod token;
pub mod token_io;
pub mod token_session;
pub mod util;
pub mod ws;

pub mod error;
mod manager;

pub use config::{
    GrantWritePolicy, LogoutMode, LogoutRange, ReplacedLoginExitMode, ReplacedRange, SaTokenConfig,
    TokenCookieConfig,
};
pub use context::{
    GrantScope, RequestAuthMeta, SaTokenContext, SaTokenContextBuilder, SaTokenContextInner,
};
pub use dao::SaTokenDao;
pub use error::{SaTokenError, SaTokenResult};
pub use keys::{
    AccountNs, KeyError, LOGIN_TYPE_DEFAULT, LOGIN_TYPE_LOGIN, LOGIN_TYPE_SSO,
    LOGIN_TYPE_SSO_CLIENT, SaKeyLayout, SaKeys,
};
pub use manager::SaTokenManager;
pub use repository::{GrantRepo, SessionRepo, TokenIdMapping, TokenRepo};
#[cfg(feature = "fory")]
pub use sa_token_adapter::serializer::ForySerializer;
pub use sa_token_adapter::serializer::{JsonSerializer, SaSerializer, SharedSerializer, ValueKind};
pub use service::{
    AuthService, AuthzService, GrantCache, GrantKind, LoginCompensator, LoginRequest,
    RollbackReport,
};
pub use stp_interface::{StorageStpInterface, StpInterface};
pub use util::{LoginId, StpUtil, TokenBuilder};

// 重新导出核心类型
pub use cleanup::{BackgroundCleanupTask, CleanupConfig};
pub use disable::{
    DEFAULT_DISABLE_LEVEL, DEFAULT_DISABLE_SERVICE, MIN_DISABLE_LEVEL, NOT_DISABLE_LEVEL,
};
pub use distributed::{
    DistributedSession, DistributedSessionManager, DistributedSessionStorage,
    InMemoryDistributedStorage, SaStorageDistributedStorage, ServiceCredential,
};
pub use event::{
    DispatchMode, EventBusConfig, LoggingListener, SaTokenEvent, SaTokenEventBus, SaTokenEventType,
    SaTokenListener,
};
pub use nonce::{NonceManager, NonceRecord};
pub use oauth2::{
    AccessToken, AuthorizationCode, CodeChallengeMethod, OAuth2Client, OAuth2Manager,
    OAuth2TokenInfo, PasswordVerifier, PkceChallenge, TokenIssueRequest,
};
pub use online::{
    DistributedOnlineStore, InMemoryPusher, LocalOnlineStore, MessagePusher, MessageType,
    OnlineManager, OnlineStore, OnlineUser, PushMessage, StoredOnlineUser,
};
pub use permission::{AntPermissionMatcher, ExactMatcher, PermissionMatcher};
pub use refresh::RefreshTokenManager;
pub use router::{
    AuthFlowResult, PathAuthConfig, extract_token, extract_token_from, match_any, match_path,
    need_auth, run_auth_flow,
};
pub use safe::{DEFAULT_SAFE_SERVICE, SAFE_AUTH_VALUE};
pub use session::SaSession;
pub use session::SaTerminalInfo;
pub use sign::{RequestSign, map_sign_err_to_sso};
pub use sso::{
    CheckTicketResult, LocalTicketChecker, NoopSloNotifier, SloNotifier, SsoClient, SsoConfig,
    SsoManager, SsoServer, SsoSession, SsoTicket, SsoTicketStore, TicketChecker,
};
#[cfg(feature = "sso-http")]
pub use sso::{HttpSloNotifier, HttpTicketChecker};
pub use stp_logic::SaLogic;
pub use temp_token::{
    DEFAULT_NAMESPACE as TEMP_TOKEN_DEFAULT_NAMESPACE, TempTokenManager, TempTokenRecord,
};
pub use token::{
    JwtAlgorithm, JwtClaims, JwtManager, TokenInfo, TokenValue, generate_unique, intern_login_type,
};
pub use token_io::{apply_token_prefix, delete_token_cookie, read_token, write_token_cookie};
pub use ws::{DefaultWsTokenExtractor, WsAuthInfo, WsAuthManager, WsTokenExtractor};
