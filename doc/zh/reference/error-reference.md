# 错误参考

[English](/reference/error-reference.md) | 中文

核心统一错误类型为 `SaTokenError`（定义于 `sa-token-core`）。用户可见的 `Display` / `message()` 文案为**英文**（与 `#[error(...)]` 一致）。

## SaTokenResult

```rust
pub type SaTokenResult<T> = Result<T, SaTokenError>;
```

业务与库 API 普遍返回该别名。也可用 `err.is_auth_error()` / `err.is_authz_error()` 做粗分类。

应用层短文案常量（非 `SaTokenError` 变体）见 `sa_token_core::error::messages`（如 `INVALID_CREDENTIALS`）。

---

## 按域分组

下列分组对照 `sa-token-core/src/error.rs`。每组附一行典型触发场景。

### Token / 登录

| 变体 | 典型触发 |
|------|----------|
| `TokenNotFound` | 存储中无此 token，或已过期被清掉 |
| `InvalidToken(String)` | token 格式/内容校验失败 |
| `TokenExpired` | 明确判定 token 已过期 |
| `NotLogin` | 当前请求上下文未登录 |
| `TokenInactive` | token 存在但未激活（如冻结/未启用） |
| `TokenEmpty` | 传入空 token 字符串 |
| `TokenTooShort` | token 长度低于校验下限 |
| `LoginIdNotNumber` | 需要数字 login_id 时解析失败 |
| `SessionNotFound` | 会话不存在或已被删除 |

### 授权（权限 / 角色 / 终端）

| 变体 | 典型触发 |
|------|----------|
| `PermissionDenied` | 权限校验失败（未带具体权限名） |
| `PermissionDeniedDetail(String)` | 缺少指定权限码 |
| `RoleDenied(String)` | 缺少指定角色 |
| `TerminalDenied { expected, actual }` | 当前设备/终端与允许模式不符 |

### 账号安全

| 变体 | 典型触发 |
|------|----------|
| `AccountBanned(String)` | 账号被封禁至指定时间 |
| `AccountKickedOut` | 被踢下线 |
| `AccountReplaced` | 其他设备顶替登录 |
| `NotSafe(String)` | 指定服务尚未通过二次认证 |
| `DisableService { service, level }` | 账号在某服务下被按等级禁用 |
| `SameTokenInvalid` | Same-Token 头缺失或不匹配 |
| `BasicAuthFailed { realm }` | HTTP Basic 凭据缺失或不匹配 |
| `SignInvalid` | 请求签名不匹配 |
| `SignTimestampExpired` | 签名时间戳缺失或超出窗口 |
| `TempTokenNotFound` | 临时令牌不存在或已删除 |
| `TempTokenExpired` | 临时令牌已过 `expire_at` |

### 初始化

| 变体 | 典型触发 |
|------|----------|
| `NotInitialized` | 未调用 `StpUtil::try_init_manager`（或等价初始化）就使用全局 API |
| `AlreadyInitialized` | 重复初始化全局 Manager |

### 存储 / 配置 / 序列化 / 内部

| 变体 | 典型触发 |
|------|----------|
| `StorageError(String)` | 底层 `SaStorage` 操作失败 |
| `ConfigError(String)` | 配置非法（如缺 storage、JWT 密钥不合规），常见于 `try_build` |
| `SerializationError(String)` | 编码/解码失败。含 `serde_json::Error`，以及可插拔 `SaSerializer` 映射来的 `SerializerError`（`EncodeFailed` / `DecodeFailed` / `FormatMismatch` / `VersionIncompatible`） |
| `InternalError(String)` | 未预期的内部错误 |

### OAuth2

| 变体 | 典型触发 |
|------|----------|
| `OAuth2ClientNotFound` | 客户端未注册 |
| `OAuth2InvalidCredentials` | client_id / secret 无效 |
| `OAuth2ClientIdMismatch` | 令牌/码与 client_id 不一致 |
| `OAuth2RedirectUriMismatch` | redirect_uri 与登记值不符 |
| `OAuth2CodeNotFound` | 授权码不存在或过期 |
| `OAuth2AccessTokenNotFound` | 访问令牌不存在或过期 |
| `OAuth2RefreshTokenNotFound` | OAuth2 刷新令牌不存在或过期 |
| `OAuth2InvalidRefreshToken` | OAuth2 刷新令牌数据无效 |
| `OAuth2InvalidScope` | scope 数据无效 |
| `OAuth2PkceRequired` | 需要 `code_verifier` 但未提供 |
| `OAuth2PkceMismatch` | PKCE 校验失败 |
| `OAuth2TokenRevokeFailed(String)` | 吊销失败 |
| `OAuth2UnsupportedGrant` | 不支持的 grant_type |
| `OAuth2PkceRequiredForPublicClient` | 公共客户端未使用 PKCE S256 |

### SSO

| 变体 | 典型触发 |
|------|----------|
| `InvalidTicket` | ticket 不存在或无效 |
| `TicketExpired` | ticket 已过期 |
| `ServiceMismatch` | service URL 与登记不符 |
| `SsoSessionNotFound` | SSO 会话不存在 |
| `SsoSignInvalid` | SSO 请求签名无效 |

### Nonce / Refresh（sa-token 刷新令牌）

| 变体 | 典型触发 |
|------|----------|
| `NonceAlreadyUsed` | nonce 已消费，疑似重放 |
| `InvalidNonceFormat` | nonce 格式无效 |
| `InvalidNonceTimestamp` | nonce 时间戳无效或过期 |
| `RefreshTokenNotFound` | 刷新令牌不存在或过期 |
| `RefreshTokenInvalidData` | 刷新令牌载荷无效 |
| `RefreshTokenMissingLoginId` | 刷新令牌缺少 login_id |
| `RefreshTokenInvalidExpireTime` | 刷新令牌过期时间格式无效 |

---

## 匹配示例

```rust
use sa_token_core::{SaTokenError, SaTokenResult};

fn map_status(err: SaTokenError) -> u16 {
    match err {
        SaTokenError::NotLogin | SaTokenError::TokenNotFound | SaTokenError::TokenExpired => 401,
        e if e.is_authz_error() => 403,
        SaTokenError::NotInitialized | SaTokenError::ConfigError(_) => 500,
        _ => 400,
    }
}
```

## 相关文档

- [快速入门](/zh/guide/quick-start.md)
- [存储](/zh/guide/storage.md)
- [安全特性](/zh/guide/security-features.md)
- [OAuth2](/zh/guide/oauth2.md)
- [SSO](/zh/guide/sso.md)
