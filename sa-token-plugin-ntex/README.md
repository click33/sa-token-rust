# sa-token-plugin-ntex

Ntex integration for **sa-token-rust**（facade）。

## 版本选择

| Feature（默认） | 绑定 crate | ntex |
|------------------|------------|------|
| `v212` | `sa-token-plugin-ntex-v212` | 2.12（Cargo 可解析同 major 的兼容版本） |

共享类型在 **`sa-token-plugin-common`**（本 crate 再导出）。路径鉴权使用 **`SaTokenLayer::with_path_auth`** + **`PathAuthConfig`**。

```toml
sa-token-plugin-ntex = { version = "0.2.0", features = ["memory"] }
ntex = "2.12"
```
