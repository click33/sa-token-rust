# sa-token-rust

[中文](/zh/)

Lightweight authentication and authorization for Rust. Inspired by [Dromara sa-token](https://github.com/dromara/sa-token); this tree is an independent implementation (MIT OR Apache-2.0). See `NOTICE` at the repository root.

It targets Web and gRPC: the same `StpUtil` / `SaTokenState` model works across Axum, Actix-web, Poem, Rocket, Warp, Salvo, Tide, Gotham, Ntex, and Tonic.

**Start here:** [Quick start](/guide/quick-start.md). Upgrading from 0.1.x: [Migrate to 0.2](/guide/migration-0.2.md).

## What you can do

Login, logout, kick-out, and replace flows are orchestrated by `AuthService`. Application code usually calls the static façade: `StpUtil::login`, `logout`, `kick_out`. Example: `let token = StpUtil::login("10001").await?;`

Permissions and roles go through `AuthzService`. Use `has_permission` / `check_role` in code, or attach macros such as `#[sa_check_permission("user:add")]`. Wildcard vs exact matching is covered in [Permissions and macros](/guide/permission-matching.md).

Path-level middleware auth uses `PathAuthConfig`. Public routes must be listed in `exclude`. `#[sa_ignore]` only skips macro-inserted checks; it does **not** bypass the Layer or middleware. See [Path auth](/guide/path-auth.md).

Memory, Redis, and Database backends go through `SaTokenDao`. Switch backends with plugin Cargo features; key layout is owned by `SaKeys`. Payload encoding defaults to JSON via pluggable `SaSerializer` / `SharedSerializer` (optional `fory` binary — see [Storage](/guide/storage.md)). Token read/write goes through core `token_io` (`read_token` / `write_token_cookie`), shared by all framework adapters.

JWT, nonce, refresh tokens, OAuth2 (with PKCE), SSO, WebSocket auth, online presence, distributed sessions, and the event bus each have dedicated guides.

Multi-account isolation uses `login_type`, for example admin vs user. Prefer `StpUtil::builder(...).login_type("admin")`, or bind a façade with `StpUtil::stp_logic("admin")?` / `manager.stp_logic("admin")` (`SaLogic` is a cheap Clone; there is no global registry).

## Project layout

```text
sa-token-rust/
├── sa-token-core/           # Dao, keys, service, token_io, oauth2/, sso/, StpUtil, SaLogic
├── sa-token-adapter/        # SaStorage, SaSerializer, SaRequest / SaResponse, scan
├── sa-token-macro/          # Procedural macros
├── sa-token-plugin-common/  # SaTokenState, rejection helpers (re-exported by plugins)
├── sa-token-storage-*/      # memory / redis / database
├── sa-token-plugin-*/       # axum, actix-web, poem, rocket, warp, salvo, tide, gotham, ntex, tonic
└── doc/                     # This site (VitePress)
```

Facade crates (Actix-web, Rocket, Salvo, Gotham, Ntex) select the framework major version via Cargo features. Shared types live in `sa-token-plugin-common`; there are no `*-core` crates anymore.

## Community

- GitHub: https://github.com/sa-tokens/sa-token-rust
- Issues: https://github.com/sa-tokens/sa-token-rust/issues

## License

MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
