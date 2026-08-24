# WebSocket authentication

English | [中文](/zh/guide/websocket-auth.md)

Use `WsAuthManager` at handshake time to read a token from headers / query and validate it. Token reading matches HTTP (`token_io`, including optional `token_prefix`).

## When to use

- WebSocket / long-lived connections should reuse the same login state as HTTP.
- You need `verify_token` for a light check, or a custom `WsTokenExtractor`.

## Minimal example

```rust
use sa_token_core::WsAuthManager;
use std::collections::HashMap;
use std::sync::Arc;

let ws_auth = WsAuthManager::new(Arc::new(manager));

let mut headers = HashMap::new();
headers.insert(
    "Authorization".into(),
    format!("Bearer {}", token_str),
);
let query = HashMap::new();

let info = ws_auth.authenticate(&headers, &query).await?;
// info.login_id / info.token / info.session_id

let login_id = ws_auth.verify_token(&info.token).await?;
```

On success a Login event is published with `login_type = "websocket"`. If the Manager has an `OnlineManager`, it calls `mark_online` (presence is connection-scoped — not the same as “has an HTTP token”).

## How the token is read

`authenticate`:

1. Calls `WsTokenExtractor::extract_token` first (default: Authorization / common query keys).
2. If empty, falls back to `token_io::read_token_from_maps(headers, query, &config)` (same `is_read_*` rules as HTTP, map-shaped).
3. Applies `apply_token_prefix` when configured.

Custom extractor:

```rust
use sa_token_core::{WsAuthManager, WsTokenExtractor};
use async_trait::async_trait;
use std::sync::Arc;

struct QueryOnly;

#[async_trait]
impl WsTokenExtractor for QueryOnly {
    async fn extract_token(
        &self,
        _headers: &HashMap<String, String>,
        query: &HashMap<String, String>,
    ) -> Option<String> {
        query.get("token").cloned()
    }
}

let ws_auth = WsAuthManager::with_extractor(Arc::new(manager), Arc::new(QueryOnly));
```

## Session helpers

- `refresh_ws_session(&auth_info)`: verify token; auto-renew if configured; refresh online activity.
- `end_ws_session(&auth_info)`: end the connection-side session and try `mark_offline`.

## Related

- [Online users](/guide/online-user-management.md)
- [Framework integration](/guide/framework-integration.md)
- [StpUtil](/guide/stp-util.md)
