# WebSocket 鉴权

[English](/guide/websocket-auth.md) | 中文

握手阶段用 `WsAuthManager` 从 Header / Query 取 token 并校验。读 token 规则与 HTTP 一致（`token_io`，含可选 `token_prefix`）。

## 何时使用

- WebSocket / 长连接握手需要与 HTTP 同一套登录态。
- 需要 `verify_token` 做轻量校验，或自定义 `WsTokenExtractor`。

## 最小示例

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

成功后会发布 `login_type = "websocket"` 的 Login 事件。若 Manager 挂了 `OnlineManager`，会 `mark_online`（presence 绑定连接，不等于「仅有 HTTP token」）。

## Token 读取

`authenticate`：

1. 先走 `WsTokenExtractor::extract_token`（默认实现看 Authorization / 常见 query）。
2. 若无结果，回退 `token_io::read_token_from_maps(headers, query, &config)`（与 HTTP 的 `is_read_header` / cookie / body 等配置一致，map 形态）。
3. 再经 `apply_token_prefix` 剥前缀。

自定义提取：

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

## 会话辅助

- `refresh_ws_session(&auth_info)`：校验 token；若开启自动续签则续期；并刷新 online 活跃时间。
- `end_ws_session(&auth_info)`：结束连接侧会话，并尽量 `mark_offline`。

## 相关链接

- [在线用户](/zh/guide/online-user-management.md)
- [框架集成](/zh/guide/framework-integration.md)
- [StpUtil](/zh/guide/stp-util.md)
