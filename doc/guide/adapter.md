# Adapters

[中文](/zh/guide/adapter.md) | English

`sa-token-adapter` defines framework-agnostic request/response traits and plugin lifecycle hooks. Official plugins already implement them. Write your own adapter only when integrating a new framework, a non-standard protocol, or when you need fake request/response objects in tests.

## When you need a custom adapter

- A framework or middleware stack not covered by official plugins
- Non-standard HTTP surfaces (custom protocols, special header/cookie rules)
- Tests that drive `token_io` or auth flows with fake request/response types

Day-to-day Axum / Actix apps should use the plugins as-is; you do not need to implement `SaRequest` / `SaResponse`.

---

## SaRequest

Read headers, cookies, query parameters, and path data from a request:

```rust
pub trait SaRequest {
    fn get_header(&self, name: &str) -> Option<String>;
    fn get_cookie(&self, name: &str) -> Option<String>;
    fn get_param(&self, name: &str) -> Option<String>;
    fn get_path(&self) -> String;
    fn get_method(&self) -> String;

    // defaults you may override
    fn get_headers(&self) -> HashMap<String, String> { HashMap::new() }
    fn get_cookies(&self) -> HashMap<String, String> { HashMap::new() }
    fn get_params(&self) -> HashMap<String, String> { HashMap::new() }
    fn get_uri(&self) -> String { self.get_path() }
    fn get_body_json<T: DeserializeOwned>(&self) -> Option<T> { None }
    fn get_client_ip(&self) -> Option<String> { None }
    fn get_user_agent(&self) -> Option<String> { self.get_header("user-agent") }
}
```

`token_io::read_token` only uses `get_header` / `get_cookie` / `get_param` (plus the `is_read_*` config flags). Middleware paths **never** consume the HTTP body.

---

## SaResponse

Write headers, cookies, status codes, and JSON bodies:

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

`CookieOptions` includes `domain` / `path` / `max_age` / `http_only` / `secure` / `same_site`. Prefer core `token_io` for login cookies so they stay aligned with `TokenCookieConfig`.

---

## token_io (core)

Unified token read/write lives in `sa_token_core::token_io`. All official plugins share this layer:

| Function | Role |
|----------|------|
| `read_token(req, config)` | Reads in `is_read_header` / `is_read_cookie` / `is_read_body` (query/param) order, then applies prefix rules |
| `apply_token_prefix(raw, prefix)` | `None`: strip optional `Bearer `; `Some(p)`: require that prefix or treat as missing |
| `write_token_cookie(res, token, config)` | Writes only when `cookie.is_write_cookie == true` |
| `delete_token_cookie(res, config)` | Clears the cookie under the same guard (`max_age = 0`) |

```rust
use sa_token_core::token_io::{
    apply_token_prefix, delete_token_cookie, read_token, write_token_cookie,
};

let token = read_token(&req, manager.config());
let stripped = apply_token_prefix("Bearer abc", None); // Some("abc")

write_token_cookie(&mut res, &token_value, manager.config());
delete_token_cookie(&mut res, manager.config());
```

Config knobs: `token_name`, `token_prefix`, `is_read_*`, `is_write_cookie`. Cookie write is off by default; turn it on for browser sessions.

For non-`SaRequest` surfaces (for example WebSocket), use `read_token_from_maps(headers, query, config)`.

---

## SaTokenPlugin

One-shot startup/shutdown hooks (replaces the removed `FrameworkAdapter`):

```rust
#[async_trait]
pub trait SaTokenPlugin: Send + Sync {
    fn name(&self) -> &str;

    async fn on_init(&self) -> Result<(), String> { Ok(()) }
    async fn on_shutdown(&self) -> Result<(), String> { Ok(()) }
}
```

Most applications never implement this. Plugin authors can register after the Manager is ready and clean up on process exit.

---

## Minimal custom request adapter

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

`sa_token_adapter::utils` also provides `parse_query_string`, `build_cookie_string`, `extract_bearer_or_value`, and related helpers.

## Related

- [Storage](./storage.md)
- [Framework integration](./framework-integration.md)
- [Quick start](./quick-start.md)
