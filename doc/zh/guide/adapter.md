# 框架适配器

[English](/guide/adapter.md) | 中文

`sa-token-adapter` 定义与具体 Web 框架无关的请求/响应与插件生命周期抽象。官方插件已经实现这些 trait；只有接入新框架、特殊协议或调试 Token 读写时才需要自己写适配层。

## 何时需要自定义适配器

- 官方尚未覆盖的框架或中间件栈
- 非标准 HTTP 表面（自定义协议、特殊 Header/Cookie 约定）
- 测试里用假请求/响应驱动 `token_io` / 鉴权流

日常 Axum / Actix 等应用直接用插件即可，不必实现 `SaRequest` / `SaResponse`。

---

## SaRequest

从请求中读取 Header、Cookie、查询参数与路径信息：

```rust
pub trait SaRequest {
    fn get_header(&self, name: &str) -> Option<String>;
    fn get_cookie(&self, name: &str) -> Option<String>;
    fn get_param(&self, name: &str) -> Option<String>;
    fn get_path(&self) -> String;
    fn get_method(&self) -> String;

    // 默认实现可按需覆盖
    fn get_headers(&self) -> HashMap<String, String> { HashMap::new() }
    fn get_cookies(&self) -> HashMap<String, String> { HashMap::new() }
    fn get_params(&self) -> HashMap<String, String> { HashMap::new() }
    fn get_uri(&self) -> String { self.get_path() }
    fn get_body_json<T: DeserializeOwned>(&self) -> Option<T> { None }
    fn get_client_ip(&self) -> Option<String> { None }
    fn get_user_agent(&self) -> Option<String> { self.get_header("user-agent") }
}
```

`token_io::read_token` 只依赖 `get_header` / `get_cookie` / `get_param`（以及配置里的 `is_read_*`），中间件路径**不会**消费 HTTP body。

---

## SaResponse

写出 Header、Cookie、状态码与 JSON 体：

```rust
pub trait SaResponse {
    fn set_header(&mut self, name: &str, value: &str);
    fn set_cookie(&mut self, name: &str, value: &str, options: CookieOptions);
    fn set_status(&mut self, status: u16);
    fn set_json_body<T: Serialize>(&mut self, body: T) -> Result<(), serde_json::Error>;

    fn delete_cookie(&mut self, name: &str) {
        self.set_cookie(
            name,
            "",
            CookieOptions { max_age: Some(0), ..Default::default() },
        );
    }
}
```

`CookieOptions` 含 `domain` / `path` / `max_age` / `http_only` / `secure` / `same_site`。登录写 Cookie 时优先走 core 的 `token_io`，以便与 `TokenCookieConfig` 一致。

---

## token_io（core）

统一 Token 读写在 `sa_token_core::token_io`，所有官方插件共用同一套逻辑：

| 函数 | 作用 |
|------|------|
| `read_token(req, config)` | 按 `is_read_header` / `is_read_cookie` / `is_read_body`（实为 query/param）顺序读取，再应用前缀 |
| `apply_token_prefix(raw, prefix)` | `None`：兼容剥离 `Bearer `；`Some(p)`：必须带此前缀，否则视为未提供 |
| `write_token_cookie(res, token, config)` | 仅当 `cookie.is_write_cookie == true` 时写入 |
| `delete_token_cookie(res, config)` | 同上开关下清除 Cookie（`max_age = 0`） |

```rust
use sa_token_core::token_io::{
    apply_token_prefix, delete_token_cookie, read_token, write_token_cookie,
};

let token = read_token(&req, manager.config());
let stripped = apply_token_prefix("Bearer abc", None); // Some("abc")

write_token_cookie(&mut res, &token_value, manager.config());
delete_token_cookie(&mut res, manager.config());
```

配置侧：`token_name`、`token_prefix`、`is_read_*`、`is_write_cookie`。默认不写 Cookie；需要浏览器会话时显式打开写 Cookie。

非 `SaRequest` 场景（如 WebSocket）可用 `read_token_from_maps(headers, query, config)`。

---

## SaTokenPlugin

应用启动/关闭时的一次性钩子（替代已删除的 `FrameworkAdapter`）：

```rust
#[async_trait]
pub trait SaTokenPlugin: Send + Sync {
    fn name(&self) -> &str;

    async fn on_init(&self) -> Result<(), String> { Ok(()) }
    async fn on_shutdown(&self) -> Result<(), String> { Ok(()) }
}
```

普通业务无需实现；插件作者可在 Manager 就绪后做注册，在进程退出前做清理。

---

## 最小自定义请求适配示例

```rust
use sa_token_adapter::context::SaRequest;
use sa_token_adapter::utils::parse_cookies;
use std::collections::HashMap;

struct MyRequest {
    headers: HashMap<String, String>,
    path: String,
    method: String,
}

impl SaRequest for MyRequest {
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers.get(name).cloned()
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        self.get_header("cookie")
            .map(|h| parse_cookies(&h))
            .and_then(|c| c.get(name).cloned())
    }

    fn get_param(&self, _name: &str) -> Option<String> { None }
    fn get_path(&self) -> String { self.path.clone() }
    fn get_method(&self) -> String { self.method.clone() }
}
```

`sa_token_adapter::utils` 还提供 `parse_query_string`、`build_cookie_string`、`extract_bearer_or_value` 等辅助函数。

## 相关文档

- [存储后端](./storage.md)
- [框架集成](./framework-integration.md)
- [快速入门](./quick-start.md)
