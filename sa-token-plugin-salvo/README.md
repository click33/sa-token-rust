# sa-token-plugin-salvo

Salvo integration for **sa-token-rust**（facade）。

## 版本选择

| Feature（默认） | 绑定 crate | Salvo |
|------------------|------------|-------|
| `v079` | `sa-token-plugin-salvo-v079` | 0.79.x |

共享类型在 **`sa-token-plugin-common`**（本 crate 再导出 `SaTokenState` 等）。

```toml
sa-token-plugin-salvo = { version = "0.2.0", features = ["memory"] }
salvo = "0.79"
```
