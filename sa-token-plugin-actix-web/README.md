# Sa-Token Actix-Web Plugin

这个包提供了 Sa-Token 与 Actix-Web 框架的集成。

## 简单使用方式

```rust
// 在你的 Cargo.toml 中添加依赖
// sa-token-plugin-actix-web = { version = "0.2.0", features = ["redis"] }

use actix_web::{web, App, HttpServer};
use sa_token_plugin_actix_web::{
    SaTokenMiddleware, SaTokenState, TokenValue, LoginId,
    sa_check_login, sa_check_permission, sa_check_role
};

// 初始化 Sa-Token 配置
fn init_sa_token() -> SaTokenState {
    SaTokenState::builder()
        .token_name("my-token")
        .timeout(7200)
        .active_timeout(1800)
        .build()
}

// 使用中间件保护路由
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 初始化 Sa-Token
    let sa_token_state = init_sa_token();

    HttpServer::new(move || {
        App::new()
            // 注册 Sa-Token 中间件
            .app_data(web::Data::new(sa_token_state.clone()))
            .wrap(SaTokenMiddleware::new(sa_token_state.clone()))
            .service(
                web::scope("/api")
                    .route("/login", web::post().to(login))
                    .route("/user_info", web::get().to(user_info))
                    .route("/admin_only", web::get().to(admin_only))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

// 登录接口
async fn login(state: web::Data<SaTokenState>) -> impl actix_web::Responder {
    // 登录逻辑
    let login_id = "user123";
    sa_token_core::StpUtil::login(login_id).await;
    
    web::Json(serde_json::json!({
        "code": 200,
        "message": "登录成功",
        "token": sa_token_core::StpUtil::get_token_value().await
    }))
}

// 需要登录才能访问的接口
#[sa_check_login]
async fn user_info(token: TokenValue) -> Result<impl actix_web::Responder, actix_web::Error> {
    // token 参数会自动从请求中提取
    // login_id 也可以通过 LoginId 提取器获取
    let login_id = sa_token_core::StpUtil::get_login_id_by_token(&token).await;
    
    Ok(web::Json(serde_json::json!({
        "code": 200,
        "data": {
            "user_id": login_id,
            "username": "测试用户"
        }
    })))
}

// 需要 admin 角色才能访问的接口
#[sa_check_role("admin")]
async fn admin_only(login_id: LoginId) -> Result<impl actix_web::Responder, actix_web::Error> {
    // login_id 参数会自动从请求中提取
    
    Ok(web::Json(serde_json::json!({
        "code": 200,
        "data": {
            "message": "只有管理员才能看到这条消息",
            "user": login_id
        }
    })))
}
```

## 特性 (Features)

- `memory` - 使用内存存储 (默认)
- `redis` - 使用 Redis 存储
- `database` - 使用数据库存储
- `full` - 包含所有存储后端

## 直接引用方式

在你的项目中，只需要添加以下依赖即可使用 Sa-Token 与 Actix-Web 的集成:

```toml
[dependencies]
sa-token-plugin-actix-web = { version = "0.2.0", features = ["redis"] }
```

这个依赖会自动包含所有必要的 Sa-Token 组件，包括核心功能和存储实现。
共享类型在 `sa-token-plugin-common`，由本 crate 再导出。
