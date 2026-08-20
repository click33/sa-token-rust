# sa-token-plugin-poem

Poem framework integration for sa-token-rust.

## Features

- ⚡ **Modern Design**: Built for Poem framework
- 🎯 **Easy Integration**: Middleware and extractors
- 🔧 **Flexible**: Comprehensive configuration options
- 🛡️ **Complete**: Full auth support

## Installation

```toml
[dependencies]
sa-token-plugin-poem = { version = "0.2.0", features = ["redis"] }
poem = "3.1"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use poem::{Route, Server, listener::TcpListener};
use sa_token_plugin_poem::{SaTokenState, SaTokenMiddleware};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .timeout(7200)
        .build();
    
    let app = Route::new()
        .at("/api/user", poem::get(user_info))
        .with(SaTokenMiddleware::new(state.manager.clone()));
    
    Server::new(TcpListener::bind("127.0.0.1:3000"))
        .run(app)
        .await
}
```

## Author

**金书记**

## License

Licensed under either of Apache-2.0 or MIT.
