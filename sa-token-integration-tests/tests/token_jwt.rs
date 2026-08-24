//! P0: JWT token integration tests.

mod common;

use common::setup;
use sa_token_core::{
    JwtAlgorithm, JwtClaims, JwtManager, SaTokenConfig, SaTokenError, config::TokenStyle,
};

const TEST_SECRET: &str = "test-secret-key-for-jwt-minimum-32-chars-long";

fn jwt_config_with_algo(algo: &str, secret: &str) -> SaTokenConfig {
    SaTokenConfig::builder()
        .token_style(TokenStyle::Jwt)
        .jwt_secret_key(secret)
        .jwt_algorithm(algo)
        .timeout(3600)
        .build_config()
}

#[tokio::test]
async fn test_jwt_generate_validate_roundtrip() {
    let mgr = setup::fresh_manager_with_config(setup::jwt_config(TEST_SECRET));
    let token = mgr.login("user_jwt").await.expect("login");
    assert!(token.as_str().contains('.'));
    assert!(mgr.is_valid(&token).await);
    let info = mgr.get_token_info(&token).await.expect("info");
    assert_eq!(info.login_id.as_ref(), "user_jwt");
}

#[tokio::test]
async fn test_jwt_standalone_roundtrip() {
    let jwt_mgr = JwtManager::new(TEST_SECRET);
    let mut claims = JwtClaims::new("user_123");
    claims.set_expiration(3600);
    let token = jwt_mgr.generate(&claims).expect("generate");
    let decoded = jwt_mgr.validate(&token).expect("validate");
    assert_eq!(decoded.login_id, "user_123");
    assert!(!decoded.is_expired());
}

#[tokio::test]
async fn test_jwt_extract_login_id() {
    let jwt_mgr = JwtManager::new(TEST_SECRET);
    let mut claims = JwtClaims::new("user_456");
    claims.set_expiration(3600);
    let token = jwt_mgr.generate(&claims).expect("generate");
    assert_eq!(
        jwt_mgr.extract_login_id(&token).expect("extract"),
        "user_456"
    );
}

#[tokio::test]
async fn test_jwt_refresh() {
    let jwt_mgr = JwtManager::new(TEST_SECRET);
    let mut claims = JwtClaims::new("user_refresh");
    claims.set_expiration(3600);
    let original = jwt_mgr.generate(&claims).expect("generate");
    let refreshed = jwt_mgr.refresh(&original, 7200).expect("refresh");
    assert_ne!(original, refreshed);
    let decoded = jwt_mgr.validate(&refreshed).expect("validate");
    assert_eq!(decoded.login_id, "user_refresh");
}

#[tokio::test]
async fn test_jwt_hs256_decode_alg() {
    let config = jwt_config_with_algo("HS256", TEST_SECRET);
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_hs256").await.expect("login");
    assert!(mgr.is_valid(&token).await);
    let jwt = JwtManager::with_algorithm(TEST_SECRET, JwtAlgorithm::HS256);
    let claims = jwt.validate(token.as_str()).expect("validate hs256");
    assert_eq!(claims.login_id, "user_hs256");
}

#[tokio::test]
async fn test_jwt_hs384_decode_alg() {
    let config = jwt_config_with_algo("HS384", TEST_SECRET);
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_hs384").await.expect("login");
    let jwt = JwtManager::with_algorithm(TEST_SECRET, JwtAlgorithm::HS384);
    let claims = jwt.validate(token.as_str()).expect("validate hs384");
    assert_eq!(claims.login_id, "user_hs384");
}

#[tokio::test]
async fn test_jwt_hs512_decode_alg() {
    let config = jwt_config_with_algo("HS512", TEST_SECRET);
    let mgr = setup::fresh_manager_with_config(config);
    let token = mgr.login("user_hs512").await.expect("login");
    let jwt = JwtManager::with_algorithm(TEST_SECRET, JwtAlgorithm::HS512);
    let claims = jwt.validate(token.as_str()).expect("validate hs512");
    assert_eq!(claims.login_id, "user_hs512");
}

#[tokio::test]
async fn test_jwt_custom_claims() {
    let jwt_mgr = JwtManager::new(TEST_SECRET);
    let mut claims = JwtClaims::new("user_claims");
    claims.set_expiration(3600);
    claims.add_claim("role", serde_json::json!("admin"));
    claims.add_claim("tenant", serde_json::json!(42));
    let token = jwt_mgr.generate(&claims).expect("generate");
    let decoded = jwt_mgr.validate(&token).expect("validate");
    assert_eq!(decoded.get_claim("role"), Some(&serde_json::json!("admin")));
    assert_eq!(decoded.get_claim("tenant"), Some(&serde_json::json!(42)));
}

#[tokio::test]
async fn test_jwt_issuer_and_audience_match() {
    let jwt_mgr = JwtManager::new(TEST_SECRET)
        .set_issuer("my-app")
        .set_audience("web-users");
    let mut claims = JwtClaims::new("user_iss");
    claims.set_expiration(3600);
    claims.set_issuer("my-app");
    claims.set_audience("web-users");
    let token = jwt_mgr.generate(&claims).expect("generate");
    let decoded = jwt_mgr.validate(&token).expect("validate");
    assert_eq!(decoded.login_id, "user_iss");
    assert_eq!(decoded.iss.as_deref(), Some("my-app"));
    assert_eq!(decoded.aud.as_deref(), Some("web-users"));
}

#[tokio::test]
async fn test_jwt_with_extra_data_via_login() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Jwt)
        .jwt_secret_key(TEST_SECRET)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let extra = serde_json::json!({"role": "admin", "tid": 42});
    let token = mgr
        .login_with_options("user_extra", None, None, Some(extra), None, None)
        .await
        .expect("login");
    let jwt_mgr = JwtManager::new(TEST_SECRET);
    let claims = jwt_mgr.validate(token.as_str()).expect("validate");
    assert_eq!(claims.get_claim("role"), Some(&serde_json::json!("admin")));
    assert_eq!(claims.get_claim("tid"), Some(&serde_json::json!(42)));
}

#[tokio::test]
async fn test_jwt_expiration_claim_past() {
    let jwt_mgr = JwtManager::new(TEST_SECRET);
    let mut claims = JwtClaims::new("user_exp");
    // 直接设过去的 exp，禁止 sleep
    claims.exp = Some(chrono::Utc::now().timestamp() - 10);
    let token = jwt_mgr.generate(&claims).expect("generate");
    setup::assert_err(jwt_mgr.validate(&token).map(|_| ()), "expired");
}

#[tokio::test]
async fn test_jwt_invalid_signature() {
    let jwt_mgr = JwtManager::new(TEST_SECRET);
    let mut claims = JwtClaims::new("user_1");
    claims.set_expiration(3600);
    let token = jwt_mgr.generate(&claims).expect("generate");
    let wrong = JwtManager::new("wrong-secret-key-minimum-32-chars-long");
    setup::assert_err(wrong.validate(&token).map(|_| ()), "invalid_token");
}

#[tokio::test]
async fn test_jwt_wrong_algorithm_rejected_or_documented() {
    let mgr_hs256 = setup::fresh_manager_with_config(jwt_config_with_algo("HS256", TEST_SECRET));
    let token = mgr_hs256.login("user_algo").await.expect("login");
    let other = JwtManager::with_algorithm(TEST_SECRET, JwtAlgorithm::HS512);
    // 契约：算法不一致应失败（jsonwebtoken 按 Validation.alg 校验）
    let result = other.validate(token.as_str());
    assert!(
        result.is_err(),
        "HS512 validator must reject HS256 token, got {result:?}"
    );
    assert!(mgr_hs256.is_valid(&token).await);
}

#[tokio::test]
async fn test_jwt_tampered_token() {
    let jwt_mgr = JwtManager::new(TEST_SECRET);
    let mut claims = JwtClaims::new("user_tamper");
    claims.set_expiration(3600);
    let token = jwt_mgr.generate(&claims).expect("generate");
    let tampered = format!("{token}x");
    setup::assert_err(jwt_mgr.validate(&tampered).map(|_| ()), "invalid_token");
}

#[tokio::test]
async fn test_jwt_empty_secret_handled() {
    let err = SaTokenConfig::builder()
        .token_style(TokenStyle::Jwt)
        .jwt_secret_key("")
        .timeout(3600)
        .try_build_config()
        .expect_err("empty jwt secret should fail");
    assert!(err.to_string().contains("jwt_secret_key"));
}

#[tokio::test]
async fn test_jwt_issuer_mismatch() {
    let jwt_mgr = JwtManager::new(TEST_SECRET).set_issuer("expected-issuer");
    let mut claims = JwtClaims::new("user_iss");
    claims.set_expiration(3600);
    claims.set_issuer("different-issuer");
    let token = jwt_mgr.generate(&claims).expect("generate");
    setup::assert_err(jwt_mgr.validate(&token).map(|_| ()), "invalid_token");
}

#[tokio::test]
async fn test_jwt_remaining_time() {
    let jwt_mgr = JwtManager::new(TEST_SECRET);
    let mut claims = JwtClaims::new("user_time");
    claims.set_expiration(3600);
    let token = jwt_mgr.generate(&claims).expect("generate");
    let decoded = jwt_mgr.validate(&token).expect("validate");
    assert!(!decoded.is_expired());
    let remaining = decoded.remaining_time().expect("remaining");
    assert!(remaining > 0);
}

#[tokio::test]
async fn test_jwt_decode_without_validation() {
    let jwt_mgr = JwtManager::new(TEST_SECRET);
    let mut claims = JwtClaims::new("user_raw");
    claims.set_expiration(3600);
    let token = jwt_mgr.generate(&claims).expect("generate");
    let decoded = jwt_mgr.decode_without_validation(&token).expect("decode");
    assert_eq!(decoded.login_id, "user_raw");
}

#[tokio::test]
async fn test_jwt_logout_invalidates_session_mapping() {
    let mgr = setup::fresh_manager_with_config(setup::jwt_config(TEST_SECRET));
    let token = mgr.login("user_jwt_logout").await.expect("login");
    assert!(mgr.is_valid(&token).await);
    mgr.logout(&token).await.expect("logout");
    assert!(!mgr.is_valid(&token).await);
    // 框架层无效；独立 JwtManager 仍可能验签通过（签名未吊销）
    let jwt = JwtManager::new(TEST_SECRET);
    let still_signed = jwt.validate(token.as_str());
    assert!(
        still_signed.is_ok(),
        "JWT signature remains valid after session logout"
    );
}
