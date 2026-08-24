# sa-token-plugin-rocket

Rocket framework integration for sa-token-rust.

## Features

- 🚀 **Rocket-native**: Built for Rocket 0.5
- 🎯 **Fairing Support**: Easy middleware integration
- 🔧 **Request Guards**: Type-safe authentication
- 🛡️ **Complete**: Full auth features

## Installation

```toml
[dependencies]
sa-token-plugin-rocket = { version = "0.2.0", features = ["redis"] }
rocket = "0.5"
```

## 版本与 crate 结构（多版本适配）

- **Facade**：本 crate（`sa-token-plugin-rocket`），默认启用 **`v05`** → 绑定 **`sa-token-plugin-rocket-v05`**（Rocket **0.5**）。
- **共享类型**：`sa-token-plugin-common`（本 crate 再导出 `SaTokenState` 等）。

## Quick Start

```rust
#[macro_use] extern crate rocket;

use rocket::State;
use sa_token_plugin_rocket::{SaTokenState, SaTokenFairing};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[get("/user/info")]
fn user_info(login_id: LoginIdGuard) -> String {
    format!("User: {}", login_id.0)
}

#[launch]
fn rocket() -> _ {
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .timeout(7200)
        .build();
    
    rocket::build()
        .attach(SaTokenFairing)
        .manage(state)
        .mount("/", routes![user_info])
}
```

## Author

**金书记**

## License

Licensed under either of Apache-2.0 or MIT.
