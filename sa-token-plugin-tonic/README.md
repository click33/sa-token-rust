# sa-token-plugin-tonic

中文 | English

Tonic gRPC 框架集成插件 | Tonic gRPC framework integration plugin

---

## 概述 | Overview

中文: 本插件为基于 [Tonic](https://github.com/hyperium/tonic) 框架构建的 gRPC 服务提供认证和授权支持。

English: This plugin provides authentication and authorization support for gRPC services built with the [Tonic](https://github.com/hyperium/tonic) framework.

---

## 功能特性 | Features

- **Tower 鉴权层 | Tower Auth Layer**: 推荐方式，支持异步 `run_auth_flow` + `PathAuthConfig` per-RPC 路径级控制
- **gRPC 拦截器 | gRPC Interceptors**: 备选方式，`block_in_place` 同步执行鉴权
- **PathAuthConfig**: Ant 风格路径规则，区分公开 / 受保护 RPC
- **类型化 Extension**: `SaTokenLoginId` / `SaTokenBearerToken`，杜绝裸 `String` 歧义
- **权限检查 | Permission Checking**: 内置角色和权限验证辅助函数

---

## 安装 | Installation

```toml
[dependencies]
sa-token-plugin-tonic = "0.2.0"

# 或使用 Redis 存储 | Or with Redis storage
sa-token-plugin-tonic = { version = "0.2.0", features = ["redis"] }
```

### 特性说明 | Features

| 特性 Feature | 说明 Description |
|-------------|-----------------|
| `tonic-012` (默认/default) | 启用 Tonic 0.12 支持 Enable Tonic 0.12 support |
| `memory` (默认/default) | 启用内存存储 Enable in-memory storage |
| `redis` | 启用 Redis 存储 Enable Redis storage |
| `database` | 启用数据库存储 Enable database storage |
| `full` | 启用所有存储后端 Enable all storage backends |

---

## 快速开始（推荐：Tower Layer）| Quick Start (Recommended: Tower Layer)

### 1. 初始化状态 | Initialize State

```rust
use sa_token_plugin_tonic::{SaTokenState, MemoryStorage};
use std::sync::Arc;

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(7200)
    .build();
```

### 2. 配置 per-RPC 鉴权规则 | Configure per-RPC Auth Rules

```rust
use sa_token_plugin_tonic::PathAuthConfig;

let path_config = PathAuthConfig::new()
    .include(vec!["/auth.AuthService/**".to_string()])
    .exclude(vec![
        "/auth.AuthService/HealthCheck".to_string(),
        "/auth.AuthService/Login".to_string(),
    ]);
```

gRPC URI path 格式为 `/<package>.<Service>/<Method>`。

### 3. 创建 Tower Layer 并启动 Server

```rust
use sa_token_plugin_tonic::SaTokenGrpcLayer;

let layer = SaTokenGrpcLayer::with_path_auth(state.clone(), path_config);

tonic::transport::Server::builder()
    .layer(tower::ServiceBuilder::new().layer(layer).into_inner())
    .add_service(my_service)
    .serve(addr)
    .await?;
```

### 4. 在 Handler 中获取登录 ID

```rust
use sa_token_plugin_tonic::get_login_id_from_request;
use tonic::{Request, Response, Status};

async fn get_user_info(
    request: Request<UserInfoRequest>,
) -> Result<Response<UserInfoResponse>, Status> {
    let login_id = get_login_id_from_request(&request)
        .ok_or_else(|| Status::unauthenticated("Not authenticated"))?;

    // login_id 是已校验的用户 ID，而非 token 字符串
    Ok(Response::new(UserInfoResponse { user_id: login_id }))
}
```

### 5. 权限检查 | Permission Checking

```rust
use sa_token_plugin_tonic::{check_permission, check_role};

async fn admin_endpoint(request: Request<()>) -> Result<Response<()>, Status> {
    let login_id = get_login_id_from_request(&request)
        .ok_or_else(|| Status::unauthenticated("Not authenticated"))?;

    if !check_permission(&login_id, "admin:write").await {
        return Err(Status::permission_denied("Insufficient permissions"));
    }

    if !check_role(&login_id, "admin").await {
        return Err(Status::permission_denied("Admin role required"));
    }

    Ok(Response::new(()))
}
```

---

## 备选方式：GrpcServerInterceptor

```rust
use sa_token_plugin_tonic::{GrpcServerInterceptor, PathAuthConfig};

let interceptor = GrpcServerInterceptor::with_path_auth(state.clone(), path_config);

let service = AuthServiceServer::with_interceptor(
    AuthServiceImpl::new(state),
    interceptor,
);
```

注意：Interceptor 内部使用 `block_in_place` 执行异步校验，需要 tokio 多线程 runtime。

---

## APISIX 透传模式 | APISIX Pass-through Mode

中文: APISIX 将客户端的 gRPC metadata 原样转发到后端，插件直接从 metadata 中读取并验证 Token，无需额外配置。

English: APISIX forwards client gRPC metadata as-is to the backend. The plugin reads and validates the token directly from metadata with no extra configuration needed.

### 客户端请求示例 | Client Request Example

```bash
# 方式1: satoken header
grpcurl -H "satoken: Bearer your-token-here" \
       -plaintext localhost:50051 auth.AuthService/GetUserInfo

# 方式2: authorization header
grpcurl -H "authorization: Bearer your-token-here" \
       -plaintext localhost:50051 auth.AuthService/GetUserInfo
```

---

## Token 读取优先级 | Token Reading Priority

| 优先级 Priority | Header 名称 Header Name | 支持格式 Supported Format |
|----------------|------------------------|--------------------------|
| 1 | `satoken` (默认/default) | `Bearer xxx` 或 or 直接 `xxx` |
| 2 | `authorization` | `Bearer xxx` |
| 3 | `Authorization` | `Bearer xxx` |

---

## 错误处理 | Error Handling

| gRPC Status | 中文条件 | English Condition |
|------------|---------|-------------------|
| `Unauthenticated` | 缺少或无效 Token | Missing or invalid token |
| `PermissionDenied` | Token 有效但权限不足 | Token valid but insufficient permissions |

---

## 与 HTTP 插件的对比 | Comparison with HTTP Plugins

| 对比项 | Comparison | HTTP 插件 | HTTP Plugin | 本插件 | This Plugin |
|--------|------------|-----------|-------------|--------|-------------|
| 工作方式 | Working Mode | HTTP Layer/Middleware | Tower Layer + gRPC Interceptor |
| 认证机制 | Auth Mechanism | `run_auth_flow` | `run_auth_flow` |
| Token 来源 | Token Source | HTTP Headers | gRPC Metadata |
| 路径规则 | Path Rules | `PathAuthConfig` | `PathAuthConfig` |

---

## Breaking Change (0.1.17)

- `get_login_id_from_request` 现在读取 `SaTokenLoginId` 类型（而非裸 `String`），必须先经 `SaTokenGrpcLayer` 或 `GrpcServerInterceptor` 校验写入
- 如需原始 token，使用 `get_bearer_token_from_request`
- `GrpcServerInterceptor` 不再「仅搬运 token」，会执行完整鉴权流水线

---

## 许可证 | License

MIT OR Apache-2.0
