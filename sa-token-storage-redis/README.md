# sa-token-storage-redis

Redis storage implementation for sa-token-rust.

## Features

- 🚀 **High Performance**: Redis-based storage with connection pooling
- 🔐 **Password Support**: Supports Redis authentication
- ⚙️ **Flexible Configuration**: Multiple initialization methods
- 🎯 **Production Ready**: Suitable for distributed deployments

## Installation

```toml
[dependencies]
sa-token-storage-redis = "0.2.0"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

### Method 1: Redis URL (Simplest)

```rust
use sa_token_storage_redis::RedisStorage;

let storage = RedisStorage::new(
    "redis://:password@localhost:6379/0",
    "sa-token:"
).await?;
```

### Method 2: RedisConfig (Structured)

```rust
use sa_token_storage_redis::{RedisStorage, RedisConfig};

let config = RedisConfig {
    host: "localhost".to_string(),
    port: 6379,
    password: Some("your-password".to_string()),
    database: 0,
    pool_size: 10,
};

let storage = RedisStorage::from_config(config, "sa-token:").await?;
```

### Method 3: Builder Pattern (Most Flexible)

```rust
use sa_token_storage_redis::RedisStorage;

let storage = RedisStorage::builder()
    .host("localhost")
    .port(6379)
    .password("your-password")
    .database(0)
    .key_prefix("sa-token:")
    .build()
    .await?;
```

## Complete Example

```rust
use sa_token_storage_redis::RedisStorage;
use sa_token_plugin_axum::SaTokenState;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = RedisStorage::new(
        "redis://:Aq23-hjPwFB3mBDNFp3W1@localhost:6379/0",
        "sa-token:"
    ).await?;
    
    let state = SaTokenState::builder()
        .storage(Arc::new(storage))
        .timeout(7200)
        .build();
    
    // Use state in your application
    Ok(())
}
```

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| host | String | localhost | Redis server address |
| port | u16 | 6379 | Redis port |
| password | Option\<String\> | None | Redis password |
| database | u8 | 0 | Database number (0-15) |
| pool_size | u32 | 10 | Connection pool size |

## Author

**金书记**

## License

Licensed under either of:
- Apache License, Version 2.0
- MIT License
