# Token 风格

[English](/guide/token-styles.md) | 中文

`TokenStyle` 控制登录时生成的 token 形态。默认 `Uuid`。JWT 需要额外密钥，详见 [JWT 指南](./jwt.md)。

## 配置

```rust
use sa_token_core::config::{SaTokenConfig, TokenStyle};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_style(TokenStyle::Random64)
    .try_build()?;
```

## TokenStyle 枚举

| 变体 | 说明 |
|------|------|
| `Uuid` | 标准 UUID（默认） |
| `SimpleUuid` | UUID 去掉横杠 |
| `Random32` | 32 字符 CSPRNG |
| `Random64` | 64 字符 CSPRNG |
| `Random128` | 128 字符 CSPRNG |
| `Jwt` | JSON Web Token；**必须**配置 `jwt_secret_key`，否则 `try_build` 失败 |
| `Hash` | 基于 login_id 的 SHA256 派生 |
| `Timestamp` | 毫秒时间戳 + 随机后缀 |
| `Tik` | 短 8 字符 token |

```rust
// JWT：密钥在构建期校验
SaTokenConfig::builder()
    .storage(storage)
    .token_style(TokenStyle::Jwt)
    .jwt_secret_key("change-me-to-a-long-secret")
    .try_build()?;
```

随机类（`Random*` / `Tik` / `Timestamp`）适合不透明会话 token；`Jwt` 适合需要自包含 claims、跨服务校验的场景。`Hash` 由 login_id 派生，多端并发登录时注意碰撞与可预测性。

## 相关链接

- [JWT](./jwt.md)
- [StpUtil](./stp-util.md)
- [快速入门](./quick-start.md)
