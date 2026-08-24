# 安全特性

[English](/guide/security-features.md) | 中文

Nonce、Refresh、二级认证（Safe）、封禁（Disable）、Same-Token、请求签名（Sign）、临时令牌（TempToken）、HTTP Basic，以及对应过程宏。

## Nonce（防重放）

配置开启后，登录可绑定一次性 nonce：

```rust
SaTokenConfig::builder()
    .enable_nonce(true)
    .nonce_timeout(60)
    // ...
```

```rust
use sa_token_core::NonceManager;

let nonce_mgr = NonceManager::from_dao(manager.dao().clone(), 60);
let nonce = nonce_mgr.generate();
nonce_mgr.store(&nonce, "user_1").await?;
nonce_mgr.validate_and_consume(&nonce, "user_1").await?;

// 或登录时带上
StpUtil::builder("user_1").nonce(nonce).login(None::<String>).await?;
```

## Refresh Token

开启后由登录流水线发放 refresh；刷新时 **同步更新** token 体、反向映射、`login:token` 与多设备索引，并删除旧 access。

```rust
SaTokenConfig::builder()
    .enable_refresh_token(true)
    .refresh_token_timeout(2_592_000)
    // ...
```

```rust
use sa_token_core::RefreshTokenManager;

let refresh = RefreshTokenManager::from_dao(manager.dao().clone());
// 或 from_storage(storage, config) / 由登录写入后取出 refresh 串
let (new_access, login_id) = refresh.refresh_access_token(&refresh_token).await?;
```

也可 `revoke_all_for_user(login_type, login_id)`。

## Safe（二级认证）

敏感操作前开启短时安全窗口：

```rust
StpUtil::open_safe("transfer", 300).await?; // 秒；当前请求 token
StpUtil::check_safe("transfer").await?;
```

宏：`#[sa_check_safe("transfer")]`。

## Disable（账号封禁）

```rust
StpUtil::disable("user_1", 86400).await?;           // 默认服务；当前 login_type
StpUtil::disable_with_type("admin", "user_1", 86400).await?;
StpUtil::disable_level("user_1", "comment", 2, 3600).await?;
let level = StpUtil::get_disable_level("user_1", "comment").await?;
StpUtil::check_disable("user_1").await?;
StpUtil::untie_disable("user_1", "comment").await?;
```

宏：`#[sa_check_disable]` / 带服务与等级参数（见宏文档）。

## Same-Token

集群内 / 网关到服务的共享口令。默认请求头 `SA-SAME-TOKEN`；当前值与上一值（宽限）均有效。

```rust
let t = StpUtil::get_same_token().await?;
StpUtil::check_same_token(&t).await?;
let t2 = StpUtil::refresh_same_token().await?;
```

宏：`#[sa_check_same_token]`（读当前请求头并校验）。

## Sign（请求签名）

配置 `sign_secret_key`（及可选 `sign_window_secs`）后：

```rust
use std::collections::BTreeMap;

let mut params = BTreeMap::new();
params.insert("userId".into(), "42".into());
let signed = StpUtil::sign_params(params).await?; // 含 timestamp / nonce / sign
StpUtil::check_sign(&signed).await?;
```

底层类型：`RequestSign`（可 `with_dao` 做 nonce 去重）。

## TempToken

短时业务令牌（默认命名空间）：

```rust
let t = StpUtil::create_temp_token("reset:user_1", 300).await?;
let record = StpUtil::parse_temp_token(&t).await?;
StpUtil::delete_temp_token(&t).await?;
```

或 `TempTokenManager::new(dao)` 指定 namespace。

## HTTP Basic

```rust
use sa_token_core::http_basic;

http_basic::check("sa-token", "admin:secret")?; // Authorization: Basic ...
```

宏：

```rust
#[sa_check_http_basic("admin:secret")]
async fn admin_only() { /* ... */ }

#[sa_check_http_basic(account = "admin:secret", realm = "sa-token")]
async fn with_realm() { /* ... */ }
```

## 相关链接

- [JWT](/zh/guide/jwt.md)
- [StpUtil](/zh/guide/stp-util.md)
- [错误参考](/zh/reference/error-reference.md)
