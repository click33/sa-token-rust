# 框架集成

[English](/guide/framework-integration.md) | 中文

各 Web 插件共享 `sa-token-plugin-common` 里的 `SaTokenState`。中间件走同一套 `run_auth_flow`；读 token 统一经 core 的 `token_io`（Header / Cookie / Body + 可选 `token_prefix`）。

## SaTokenState

```rust
use sa_token_plugin_axum::*; // 或其它插件门面
use std::sync::Arc;

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_name("Authorization")
    .timeout(86400)
    .is_read_header(true)
    .build(); // 内部 try_init_manager；库代码也可 SaTokenConfig::try_build
```

不要再依赖已删除的 `sa-token-plugin-*-core`。

## Axum：Layer + Extractor

```rust
use axum::{Router, routing::{get, post}};
use sa_token_plugin_axum::*;

let path_auth = PathAuthConfig::new()
    .include(vec!["/**".into()])
    .exclude(vec!["/api/login".into(), "/api/health".into()]);

let app = Router::new()
    .route("/api/login", post(login))
    .route("/api/me", get(me))
    .layer(SaTokenLayer::with_path_auth(state.clone(), path_auth))
    .with_state(state);

async fn me(SaTokenExtractor(token): SaTokenExtractor) -> String {
    token.as_str().to_string()
}
// 另有 OptionalSaTokenExtractor、LoginIdExtractor
```

公开路由必须 `PathAuthConfig::exclude`；`#[sa_ignore]` 只跳过宏检查，不跳过 Layer。

## Actix-web：Middleware

门面默认 **`v4`**。feature **`v5` 仅为占位**，单独启用会 `compile_error!`，生产请用 `v4`。

```toml
sa-token-plugin-actix-web = "0.2.0" # default features = ["v4", ...]
```

```rust
use actix_web::{App, HttpServer, web};
use sa_token_plugin_actix_web::*;

HttpServer::new(move || {
    App::new()
        .app_data(web::Data::new(state.clone()))
        .wrap(SaTokenMiddleware::with_path_auth(
            state.clone(),
            PathAuthConfig::new()
                .include(vec!["/**".into()])
                .exclude(vec!["/api/login".into()]),
        ))
        .route("/api/login", web::post().to(login))
})
```

## 其它插件（短表）

| 框架 | Crate | 说明 |
|------|-------|------|
| Poem | `sa-token-plugin-poem` | `SaTokenLayer::with_path_auth` |
| Warp | `sa-token-plugin-warp` | 一体化 |
| Tide | `sa-token-plugin-tide` | 一体化 |
| Rocket | `sa-token-plugin-rocket` | 门面，feature 选大版本 |
| Salvo | `sa-token-plugin-salvo` | 门面 |
| Gotham | `sa-token-plugin-gotham` | 门面 |
| Ntex | `sa-token-plugin-ntex` | 门面 |
| Tonic | `sa-token-plugin-tonic` | gRPC Layer + PathAuth |

## Token 读取（token_io）

插件适配器把请求变成 `SaRequest` 后调用：

- `token_io::read_token` — 按 `is_read_header` / `is_read_cookie` / `is_read_body` 与 `token_name`
- `apply_token_prefix` — 可选前缀
- 写回：`is_write_cookie` + `write_token_cookie`

WebSocket 握手的 map 形态见 `read_token_from_maps`（[WebSocket 鉴权](/zh/guide/websocket-auth.md)）。

## 相关链接

- [快速入门](/zh/guide/quick-start.md)
- [路径鉴权](/zh/guide/path-auth.md)
- [适配器](/zh/guide/adapter.md)
