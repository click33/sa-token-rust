# sa-token-storage-database

Database storage implementation for sa-token-rust (0.2.0).

## Status

Basic KV (`get` / `set` / `delete` / …) is available. Advanced ops are **Unsupported** in this release:

- `get_del` / CAS / `set_if_absent`
- `list_push` / `list_remove` / list helpers
- `scan`

Do not use this backend for nonce one-shot consume, online indexes, or multi-device lists until a later storage plan. See [MIGRATION_0.2.md](../MIGRATION_0.2.md) §5.

## Install

```toml
[dependencies]
sa-token-storage-database = "0.2.0"
```

## License

MIT OR Apache-2.0
