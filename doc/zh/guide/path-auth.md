# 路径鉴权

[English](/guide/path-auth.md) | 中文

HTTP / gRPC 中间件通过 `PathAuthConfig` 决定「哪些路径必须登录」。公开接口请用 `exclude`，**不要**指望 `#[sa_ignore]`（它只跳过宏检查）。

## 何时使用

- 整站默认鉴权，仅放行 `/login`、`/health` 等。
- 与 `#[sa_check_*]` 分工：中间件管「有没有登录」，宏管「有没有权限 / 角色」。

## PathAuthConfig

```rust
use sa_token_core::router::PathAuthConfig;

let config = PathAuthConfig::new()
    .include(vec!["/**".into()])           // 需要鉴权的路径（Ant 风格）
    .exclude(vec![
        "/api/login".into(),
        "/health".into(),
        "/public/**".into(),
    ])
    .validator(|login_id| {                 // 可选：额外校验 login_id
        !login_id.is_empty()
    });
```

规则：`need_auth = 匹配 include 且不匹配 exclude`。

| 模式 | 含义 |
|------|------|
| `/**` | 全部路径 |
| `/api/**` | 以 `/api` 为前缀 |
| `/api/*` | `/api` 下仅一层（`/api/user` 命中，`/api/a/b` 不命中） |
| `*.html` | 以 `.html` 结尾 |
| `/exact` | 精确匹配 |

## run_auth_flow

各框架 Layer / Middleware 内部调用同一流水线：

```text
extract_token_from(req, config)
  → process_auth(path, token, PathAuthConfig?, manager)
  → create_context → AuthFlowResult
```

```rust
use sa_token_core::router::run_auth_flow;

// path_config = Some(...)：按 include/exclude 决定是否 401
// path_config = None：有 token 则校验并填上下文，不按路径拒绝
let flow = run_auth_flow(&adapter, &manager, Some(&config)).await;
if flow.should_reject() {
    // 绑定层返回 401
}
```

`AuthFlowResult::run(fut)` 会在 `SaTokenContext::scope` 中执行后续 handler，供 `StpUtil` 无参 API 使用。

## Layer：`with_path_auth` vs 宏

**Axum 示例：**

```rust
use sa_token_plugin_axum::{SaTokenLayer, SaTokenState};
use sa_token_core::PathAuthConfig;

let state = SaTokenState::builder()
    .storage(storage)
    .build();

let path = PathAuthConfig::new()
    .include(vec!["/**".into()])
    .exclude(vec!["/api/login".into()]);

let app = axum::Router::new()
    .route("/api/login", /* ... */)
    .route("/api/user", /* ... */)
    .layer(SaTokenLayer::with_path_auth(state.clone(), path));
```

**Actix 示例：**

```rust
use sa_token_plugin_actix_web::{PathAuthConfig, SaTokenMiddleware};

App::new().wrap(SaTokenMiddleware::with_path_auth(
    state.clone(),
    PathAuthConfig::new()
        .include(vec!["/**".into()])
        .exclude(vec!["/api/login".into()]),
))
```

| 机制 | 作用 | 不做什么 |
|------|------|----------|
| `SaTokenLayer::with_path_auth` / `SaTokenMiddleware::with_path_auth` | 路径级登录门禁；写上下文 | 不检查权限字符串 |
| `#[sa_check_login]` / `#[sa_check_permission]` | 处理器内细粒度检查 | **不**放行中间件 |
| `#[sa_ignore]` | 本函数不插入宏检查 | **不**跳过 Layer |

仅构造 `SaTokenLayer::new(state)`（无 path config）时：有 token 则填充上下文，匿名请求默认放行——适合「路由自己用宏保护」的模式。

## 陷阱

1. 忘记 `exclude` 登录接口 → 客户端永远 401。
2. 只加 `#[sa_ignore]` 却未 `exclude` → 中间件仍拒绝。
3. `include` 为空 → 任何路径都不会 `need_auth`（等于关掉路径强制登录）。

## 相关链接

- 仓库示例：`cargo run --example path_auth_example`（[`examples/path_auth_example.rs`](https://github.com/sa-tokens/sa-token-rust/blob/main/examples/path_auth_example.rs)）
- [StpUtil](./stp-util.md)
- [权限匹配与宏](./permission-matching.md)
- [框架集成](./framework-integration.md)
