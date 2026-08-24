# JWT

[English](/guide/jwt.md) | 中文

把登录 token 发成 JWT：配置 `TokenStyle::Jwt` 与 `jwt_secret_key`，由 `try_build` 在启动时校验。需要独立签发/验签时，可用 `JwtManager`。

## 何时使用

- 下游服务要本地验签、少查存储。
- 希望 token 自带 `login_id`、过期时间与自定义 claims。
- 仍走 sa-token 登录/登出流水线，只是 token 形态换成 JWT。

## 配置与 try_build

`TokenStyle::Jwt` 时 **必须** 设置非空 `jwt_secret_key`，否则 `try_build` / `try_build_config` 失败。

`jwt_fallback_on_error` 默认 **`false`**：JWT 生成失败会直接报错，不会静默退化成 UUID。仅在你明确接受降级时再打开。

```rust
use sa_token_core::{SaTokenConfig, TokenStyle};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_style(TokenStyle::Jwt)
    .jwt_secret_key("change-me-to-a-long-secret")
    .jwt_algorithm("HS256") // 可选
    .jwt_issuer("my-app")   // 可选
    .jwt_audience("api")    // 可选
    // .jwt_fallback_on_error(true) // 默认 false，勿轻易开启
    .try_build()?;
```

插件侧等价：

```rust
use sa_token_plugin_axum::*;

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_style(TokenStyle::Jwt)
    .jwt_secret_key("change-me-to-a-long-secret")
    .build();
```

登录后拿到的字符串即为 JWT；校验仍走 `StpUtil` / Manager 的 token 信息读取（内部验签并落存储契约）。

## JwtManager（独立签发）

不经过登录流水线、只做 JWT 编解码时：

```rust
use sa_token_core::{JwtClaims, JwtManager};

let jwt = JwtManager::new("change-me-to-a-long-secret")
    .set_issuer("my-app")
    .set_audience("api");

let mut claims = JwtClaims::new("user_10086");
claims.set_expiration(3600);
claims.set_login_type("user");
claims.add_claim("role", serde_json::json!("admin"));

let token = jwt.generate(&claims)?;
let decoded = jwt.validate(&token)?;
assert_eq!(decoded.login_id, "user_10086");
```

常用方法：`generate`、`validate`、`refresh`、`extract_login_id`。算法见 `JwtAlgorithm`（默认 HS256）。

## 陷阱

| 点 | 说明 |
|----|------|
| 密钥 | 生产环境用足够长的随机密钥；不要提交进仓库 |
| fallback | 保持默认 `false`，避免「看起来登录成功、实际不是 JWT」 |
| 与存储 | JWT 风格仍会写 token 映射/索引；不是纯无状态除非你另做设计 |

## 相关链接

- [Token 风格](/zh/guide/token-styles.md)
- [安全特性](/zh/guide/security-features.md)
- [错误参考](/zh/reference/error-reference.md)
