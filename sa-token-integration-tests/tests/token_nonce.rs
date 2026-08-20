//! P1: Nonce integration tests.
//!
//! Covers nonce generation, validation, consumption (replay detection),
//! TTL expiry, timestamp checking, and error paths.

mod common;

use sa_token_core::{NonceManager, SaTokenError};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

fn nonce_mgr(ttl: i64) -> NonceManager {
    NonceManager::new(Arc::new(MemoryStorage::new()), ttl)
}

// ── Success cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_generate_nonce_returns_unique() {
    let mgr = nonce_mgr(60);
    let n1 = mgr.generate();
    let n2 = mgr.generate();
    assert_ne!(n1, n2, "each nonce should be unique");
    assert!(n1.starts_with("nonce_"));
    assert!(n2.starts_with("nonce_"));
}

#[tokio::test]
async fn test_validate_and_consume_succeeds_first_time() {
    let mgr = nonce_mgr(60);
    let nonce = mgr.generate();
    let result = mgr.validate_and_consume(&nonce, "user_123").await;
    assert!(result.is_ok(), "first consume should succeed");
}

#[tokio::test]
async fn test_validate_returns_true_for_new_nonce() {
    let mgr = nonce_mgr(60);
    let nonce = mgr.generate();
    let valid = mgr.validate(&nonce).await.expect("validate");
    assert!(valid, "new nonce should be valid (not yet consumed)");
}

#[tokio::test]
async fn test_check_timestamp_within_window() {
    let mgr = nonce_mgr(60);
    let nonce = mgr.generate();
    // Freshly generated nonce should be within 60 second window
    let ok = mgr.check_timestamp(&nonce, 60).expect("check_timestamp");
    assert!(ok, "fresh nonce timestamp should be within window");
    // Should also be valid for 1-second window (just generated)
    let ok1 = mgr.check_timestamp(&nonce, 1).expect("check_timestamp 1s");
    assert!(ok1);
}

#[tokio::test]
async fn test_store_then_validate_returns_false() {
    let mgr = nonce_mgr(60);
    let nonce = mgr.generate();
    mgr.store(&nonce, "user_123").await.expect("store");
    let valid = mgr.validate(&nonce).await.expect("validate");
    assert!(!valid, "stored nonce should be invalid (already used)");
}

#[tokio::test]
async fn test_nonce_ttl_expiry() {
    let mgr = nonce_mgr(1); // 1 second TTL
    let nonce = mgr.generate();
    mgr.store(&nonce, "user_123").await.expect("store");
    // Nonce consumed — validate should return false
    assert!(!mgr.validate(&nonce).await.unwrap());
    // Wait for TTL to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // After TTL expiry, storage removes it. It's not "valid" per se —
    // it was already consumed. But a new identical value shouldn't exist.
    // After expiry, the key is gone from storage, but validate still
    // returns false because the nonce was logically consumed.
    let post = mgr.validate(&nonce).await.unwrap();
    // After TTL, the consumed record is cleaned. The nonce is now
    // "valid" again (not found in storage = not yet used).
    assert!(post);
}

// ── Failure cases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_double_consume_replay_detected() {
    let mgr = nonce_mgr(60);
    let nonce = mgr.generate();
    // First use succeeds
    mgr.validate_and_consume(&nonce, "user_123")
        .await
        .expect("first");
    // Second use = replay attack
    let result = mgr.validate_and_consume(&nonce, "user_123").await;
    assert!(result.is_err(), "replay should be rejected");
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::NonceAlreadyUsed
    ));
}

#[tokio::test]
async fn test_invalid_nonce_format_timestamp_check() {
    let mgr = nonce_mgr(60);
    // Malformed nonce should fail timestamp check
    let result = mgr.check_timestamp("not_a_valid_nonce", 60);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::InvalidNonceFormat
    ));
}

#[tokio::test]
async fn test_bad_timestamp_in_nonce() {
    let mgr = nonce_mgr(60);
    // nonce_bad_xyz — "bad" is not a valid timestamp
    let result = mgr.check_timestamp("nonce_bad_xyz", 60);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SaTokenError::InvalidNonceTimestamp
    ));
}

#[tokio::test]
async fn test_nonce_timestamp_outside_window() {
    let mgr = nonce_mgr(60);
    // Generate a nonce with a very old timestamp by constructing one manually
    let old_nonce = format!("nonce_{}_oldhash123456789012345678901234567890", 1000); // timestamp from 1970
    // This timestamp is way too old
    let result = mgr.check_timestamp(&old_nonce, 60);
    // Should be outside the 60-second window
    assert!(result.is_ok()); // parse succeeds
    assert!(!result.unwrap(), "old timestamp should be outside window");
}

#[tokio::test]
async fn test_cleanup_is_noop() {
    let mgr = nonce_mgr(60);
    let result = mgr.cleanup_expired().await;
    assert!(
        result.is_ok(),
        "cleanup should succeed (noop for memory storage)"
    );
}
