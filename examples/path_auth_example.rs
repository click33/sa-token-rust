// Author: 金书记
//
//! 路径鉴权示例 | Path-auth example
//!
//! 演示 `PathAuthConfig`、Ant 路径匹配、`process_auth` / `run_auth_flow`。
//! Demonstrates `PathAuthConfig`, Ant-style matching, `process_auth` / `run_auth_flow`.
//!
//! 运行 | Run:
//! ```bash
//! cargo run --example path_auth_example
//! ```
//!
//! Web 框架中请用 `SaTokenLayer::with_path_auth` / `SaTokenMiddleware::with_path_auth`，
//! 公开路由必须写在 `exclude` 里；`#[sa_ignore]` 不会跳过中间件。
//! In Web apps use `with_path_auth`; public routes belong in `exclude`.
//! `#[sa_ignore]` does not bypass the Layer.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::collections::HashMap;
use std::sync::Arc;

use sa_token_adapter::context::SaRequest;
use sa_token_core::{
    SaTokenConfig, StpUtil,
    router::{
        PathAuthConfig, match_path, need_auth, process_auth, run_auth_flow,
    },
};
use sa_token_storage_memory::MemoryStorage;

/// 简易请求桩，模拟 Header / Cookie / Query | Minimal SaRequest stub
struct DemoRequest {
    headers: HashMap<String, String>,
    cookies: HashMap<String, String>,
    params: HashMap<String, String>,
    path: String,
    method: String,
}

impl DemoRequest {
    fn get(path: &str) -> Self {
        Self {
            headers: HashMap::new(),
            cookies: HashMap::new(),
            params: HashMap::new(),
            path: path.to_string(),
            method: "GET".to_string(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }
}

impl SaRequest for DemoRequest {
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers.get(name).cloned()
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        self.cookies.get(name).cloned()
    }

    fn get_param(&self, name: &str) -> Option<String> {
        self.params.get(name).cloned()
    }

    fn get_path(&self) -> String {
        self.path.clone()
    }

    fn get_method(&self) -> String {
        self.method.clone()
    }
}

fn print_section(title: &str) {
    println!("\n{}", "=".repeat(60));
    println!("{title}");
    println!("{}", "=".repeat(60));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("sa-token path-auth example | 路径鉴权示例\n");

    // ------------------------------------------------------------------
    // 1. Ant 风格匹配 | Ant-style matching
    // ------------------------------------------------------------------
    print_section("1. match_path / need_auth");

    let cases = [
        ("/api/user", "/api/**", true),
        ("/api/user/profile", "/api/*", false),
        ("/api/user", "/api/*", true),
        ("/page.html", "*.html", true),
        ("/health", "/**", true),
    ];
    for (path, pattern, expect) in cases {
        let hit = match_path(path, pattern);
        println!("  match_path({path:?}, {pattern:?}) = {hit} (expect {expect})");
        assert_eq!(hit, expect);
    }

    let include = ["/api/**"];
    let exclude = ["/api/login", "/api/public/**"];
    for path in ["/api/user", "/api/login", "/api/public/info", "/health"] {
        let need = need_auth(path, &include, &exclude);
        println!("  need_auth({path:?}) = {need}");
    }

    // ------------------------------------------------------------------
    // 2. PathAuthConfig + 登录 | PathAuthConfig + login
    // ------------------------------------------------------------------
    print_section("2. PathAuthConfig + StpUtil::login");

    let manager = SaTokenConfig::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .token_name("sa-token")
        .timeout(3600)
        .try_build()?;

    let path_cfg = PathAuthConfig::new()
        .include(vec!["/**".into()])
        .exclude(vec![
            "/health".into(),
            "/api/login".into(),
            "/public/**".into(),
        ])
        .validator(|login_id| !login_id.is_empty());

    println!("  /health     need_auth = {}", path_cfg.check("/health"));
    println!("  /api/login  need_auth = {}", path_cfg.check("/api/login"));
    println!("  /api/me     need_auth = {}", path_cfg.check("/api/me"));
    println!(
        "  /public/a   need_auth = {}",
        path_cfg.check("/public/a")
    );

    let token = StpUtil::login("user_10001").await?;
    println!("  logged in as user_10001, token = {token}");

    // ------------------------------------------------------------------
    // 3. process_auth：有无 token | process_auth with / without token
    // ------------------------------------------------------------------
    print_section("3. process_auth");

    let protected = process_auth("/api/me", None, &path_cfg, &manager).await;
    println!(
        "  /api/me without token: need_auth={}, should_reject={}",
        protected.need_auth,
        protected.should_reject()
    );

    let ok = process_auth(
        "/api/me",
        Some(token.as_str().to_string()),
        &path_cfg,
        &manager,
    )
    .await;
    println!(
        "  /api/me with token:    need_auth={}, is_valid={}, login_id={:?}",
        ok.need_auth,
        ok.is_valid,
        ok.login_id()
    );

    let public = process_auth("/health", None, &path_cfg, &manager).await;
    println!(
        "  /health without token: need_auth={}, should_reject={}",
        public.need_auth,
        public.should_reject()
    );

    // ------------------------------------------------------------------
    // 4. run_auth_flow：模拟 HTTP Header | run_auth_flow via header
    // ------------------------------------------------------------------
    print_section("4. run_auth_flow (header sa-token)");

    let req_ok = DemoRequest::get("/api/me").with_header("sa-token", token.as_str());
    let flow_ok = run_auth_flow(&req_ok, &manager, Some(&path_cfg)).await;
    println!(
        "  with valid header: should_reject={}, login_id={:?}",
        flow_ok.should_reject(),
        flow_ok.login_id
    );

    let req_anon = DemoRequest::get("/api/me");
    let flow_anon = run_auth_flow(&req_anon, &manager, Some(&path_cfg)).await;
    println!(
        "  without header:    should_reject={} (middleware would return 401)",
        flow_anon.should_reject()
    );

    let req_public = DemoRequest::get("/api/login");
    let flow_public = run_auth_flow(&req_public, &manager, Some(&path_cfg)).await;
    println!(
        "  /api/login exclude: should_reject={}",
        flow_public.should_reject()
    );

    // path_config = None：有 token 则填充上下文，不按路径拒绝
    // None: validate token when present; never reject by path
    let req_optional = DemoRequest::get("/anything").with_header("sa-token", token.as_str());
    let flow_optional = run_auth_flow(&req_optional, &manager, None).await;
    println!(
        "  path_config=None:   should_reject={}, login_id={:?}",
        flow_optional.should_reject(),
        flow_optional.login_id
    );

    println!("\nDone. Tip: in Axum use SaTokenLayer::with_path_auth(state, path_cfg).");
    Ok(())
}
