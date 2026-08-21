//! 路径鉴权路由：`match_path` / `need_auth` / `extract_token` / `run_auth_flow`。
//!
//! 过期用灰盒拨钟，禁止 sleep。Layer 级 path_auth 见 `plugin_axum` / `plugin_actix`。

mod common;

use common::setup;
use sa_token_adapter::context::SaRequest;
use sa_token_core::router::{
    PathAuthConfig, extract_token, match_any, match_path, need_auth, run_auth_flow,
};
use std::collections::HashMap;

// ── Mock SaRequest ────────────────────────────────────────────────────────

struct MockRequest {
    headers: HashMap<String, String>,
    cookies: HashMap<String, String>,
    params: HashMap<String, String>,
    path: String,
    method: String,
}

impl MockRequest {
    fn new(path: &str) -> Self {
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

    fn with_cookie(mut self, name: &str, value: &str) -> Self {
        self.cookies.insert(name.to_string(), value.to_string());
        self
    }

    fn with_param(mut self, name: &str, value: &str) -> Self {
        self.params.insert(name.to_string(), value.to_string());
        self
    }
}

impl SaRequest for MockRequest {
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

// ── match_path / need_auth / PathAuthConfig ───────────────────────────────

#[test]
fn test_match_path_exact() {
    assert!(match_path("/api/user", "/api/user"));
    assert!(!match_path("/api/user", "/api/admin"));
}

#[test]
fn test_match_path_double_star() {
    assert!(match_path("/api/user", "/api/**"));
    assert!(match_path("/api/user/profile", "/api/**"));
    assert!(match_path("/api/a/b/c/d", "/api/**"));
    assert!(!match_path("/other/user", "/api/**"));
}

#[test]
fn test_match_path_single_star() {
    assert!(match_path("/api/user", "/api/*"));
    assert!(!match_path("/api/user/profile", "/api/*"));
    assert!(match_path("/api/", "/api/*"));
}

#[test]
fn test_match_path_suffix() {
    assert!(match_path("/page.html", "*.html"));
    assert!(match_path("/sub/page.html", "*.html"));
    assert!(!match_path("/page.htm", "*.html"));
}

#[test]
fn test_match_path_all() {
    assert!(match_path("/anything", "/**"));
    assert!(match_path("/", "/**"));
    assert!(match_path("/a/b/c", "/**"));
}

#[test]
fn test_match_any_matches_first() {
    let patterns = ["/api/**", "/admin/**"];
    assert!(match_any("/api/user", &patterns));
    assert!(match_any("/admin/dashboard", &patterns));
    assert!(!match_any("/public/page", &patterns));
}

#[test]
fn test_need_auth_include_only() {
    let include = ["/api/**"];
    let exclude = [];
    assert!(need_auth("/api/user", &include, &exclude));
    assert!(!need_auth("/public/page", &include, &exclude));
}

#[test]
fn test_need_auth_exclude_overrides() {
    let include = ["/api/**"];
    let exclude = ["/api/public/**"];
    assert!(need_auth("/api/user", &include, &exclude));
    assert!(!need_auth("/api/public/info", &include, &exclude));
}

#[test]
fn test_need_auth_no_include_returns_false() {
    let include = [];
    let exclude = ["/api/**"];
    assert!(!need_auth("/api/user", &include, &exclude));
}

#[test]
fn test_path_auth_config_include_exclude() {
    let config = PathAuthConfig::new()
        .include(vec!["/api/**".into(), "/admin/**".into()])
        .exclude(vec!["/api/public/**".into(), "/api/health".into()]);
    assert!(config.check("/api/user"));
    assert!(config.check("/admin/dashboard"));
    assert!(!config.check("/api/public/info"));
    assert!(!config.check("/api/health"));
    assert!(!config.check("/public/home"));
}

#[test]
fn test_path_auth_config_with_validator() {
    let config = PathAuthConfig::new()
        .include(vec!["/api/**".into()])
        .validator(|login_id| login_id.starts_with("user_"));
    assert!(config.check("/api/data"));
    assert!(config.validate_login_id("user_123"));
    assert!(!config.validate_login_id("admin_123"));
}

#[test]
fn test_match_path_no_match() {
    assert!(!match_path("/api/user", "/other/*"));
    assert!(!match_path("/about", "/api/**"));
    assert!(!match_path("/page.htm", "*.html"));
}

// ── extract_token：Header / Cookie / Query / Bearer ───────────────────────

#[test]
fn test_extract_token_from_header() {
    let req = MockRequest::new("/api/user").with_header("sa-token", "my_token_value");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("my_token_value"));
}

#[test]
fn test_extract_token_bearer_prefix() {
    let req = MockRequest::new("/api/user").with_header("sa-token", "Bearer my_jwt_token");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("my_jwt_token"));
}

#[test]
fn test_extract_token_from_cookie() {
    let req = MockRequest::new("/api/user").with_cookie("sa-token", "cookie_token_value");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("cookie_token_value"));
}

#[test]
fn test_extract_token_from_query() {
    let req = MockRequest::new("/api/user").with_param("sa-token", "query_token_value");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("query_token_value"));
}

#[test]
fn test_extract_token_header_priority_over_cookie() {
    let req = MockRequest::new("/api/user")
        .with_header("sa-token", "header_token")
        .with_cookie("sa-token", "cookie_token");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("header_token"));
}

#[test]
fn test_extract_token_falls_back_to_authorization_header() {
    let req = MockRequest::new("/api/user").with_header("Authorization", "Bearer auth_token");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("auth_token"));
}

#[test]
fn test_extract_token_no_token() {
    let req = MockRequest::new("/api/user");
    let token = extract_token(&req, "sa-token");
    assert!(token.is_none());
}

#[test]
fn test_extract_token_empty_header_value_skipped() {
    let req = MockRequest::new("/api/user").with_header("sa-token", "");
    let token = extract_token(&req, "sa-token");
    assert!(token.is_none(), "empty header value should be skipped");
}

// ── run_auth_flow ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_run_auth_flow_valid_token() {
    let mgr = setup::fresh_manager();
    let id = setup::unique_login_id("user_router");
    let token = mgr.login(&id).await.expect("login");
    let req = MockRequest::new("/api/user").with_header("sa-token", token.as_str());
    let flow = run_auth_flow(&req, &mgr, None).await;
    assert!(!flow.should_reject());
    assert_eq!(flow.login_id.as_deref(), Some(id.as_str()));
}

#[tokio::test]
async fn test_run_auth_flow_with_path_config() {
    let mgr = setup::fresh_manager();
    let id = setup::unique_login_id("user_path");
    let token = mgr.login(&id).await.expect("login");
    let path_config = PathAuthConfig::new()
        .include(vec!["/api/**".into()])
        .exclude(vec!["/api/public/**".into()]);
    let req = MockRequest::new("/api/user").with_header("sa-token", token.as_str());
    let flow = run_auth_flow(&req, &mgr, Some(&path_config)).await;
    assert!(!flow.should_reject());
    assert_eq!(flow.login_id.as_deref(), Some(id.as_str()));
}

#[tokio::test]
async fn test_auth_flow_result_run_scope() {
    let mgr = setup::fresh_manager();
    let id = setup::unique_login_id("user_scope");
    let token = mgr.login(&id).await.expect("login");
    let req = MockRequest::new("/api/data").with_header("sa-token", token.as_str());
    let flow = run_auth_flow(&req, &mgr, None).await;
    let result = flow.run(async { "handler_result" }).await;
    assert_eq!(result, "handler_result");
}

#[tokio::test]
async fn test_run_auth_flow_no_token_path_requires_auth() {
    let mgr = setup::fresh_manager();
    let path_config = PathAuthConfig::new().include(vec!["/api/**".into()]);
    let req = MockRequest::new("/api/user");
    let flow = run_auth_flow(&req, &mgr, Some(&path_config)).await;
    assert!(
        flow.should_reject(),
        "no token + path requires auth → reject"
    );
}

#[tokio::test]
async fn test_run_auth_flow_expired_token() {
    let mgr = setup::fresh_manager();
    let id = setup::unique_login_id("user_exp_router");
    let token = mgr.login(&id).await.expect("login");
    setup::expire_token(&mgr, &token).await;
    let path_config = PathAuthConfig::new().include(vec!["/api/**".into()]);
    let req = MockRequest::new("/api/user").with_header("sa-token", token.as_str());
    let flow = run_auth_flow(&req, &mgr, Some(&path_config)).await;
    assert!(
        flow.should_reject(),
        "expired token + path requires auth → reject"
    );
}

#[tokio::test]
async fn test_run_auth_flow_no_path_config_no_token_no_reject() {
    let mgr = setup::fresh_manager();
    let req = MockRequest::new("/public/hello");
    let flow = run_auth_flow(&req, &mgr, None).await;
    assert!(
        !flow.should_reject(),
        "no path config → no reject on missing token"
    );
    assert!(flow.login_id.is_none());
}
