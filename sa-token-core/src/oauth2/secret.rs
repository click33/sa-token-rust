// Author: 金书记 | Author: Jin Shuji
//! Client secret hashing (Argon2id) and verification.
//! 客户端密钥的 Argon2id 哈希与校验。

use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier as ArgonVerifier, SaltString,
        rand_core::OsRng,
    },
};

use crate::error::{SaTokenError, SaTokenResult};

/// PHC prefix used to detect hashed secrets vs legacy plaintext.
/// 用于区分哈希串与历史明文的 PHC 前缀。
pub(super) const ARGON2_PREFIX: &str = "$argon2";

/// Hash / verify client secrets.
/// 客户端密钥哈希与校验。
pub struct ClientSecretHasher;

impl ClientSecretHasher {
    /// Hash a plaintext secret (OS random salt).
    /// 哈希明文密钥（操作系统随机盐）。
    pub fn hash_plain_secret(plain: &str) -> SaTokenResult<String> {
        if plain.is_empty() {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(plain.as_bytes(), &salt)
            .map_err(|e| SaTokenError::InternalError(format!("hash client secret failed: {e}")))?;
        Ok(hash.to_string())
    }

    /// True if `stored` looks like an Argon2 PHC string.
    /// `stored` 是否像 Argon2 PHC 串。
    pub fn is_hashed(stored: &str) -> bool {
        stored.starts_with(ARGON2_PREFIX)
    }

    /// Verify plaintext against stored hash.
    /// 校验明文是否匹配已存哈希。
    pub fn verify_plain_secret(plain: &str, stored_hash: &str) -> SaTokenResult<bool> {
        let parsed =
            PasswordHash::new(stored_hash).map_err(|_| SaTokenError::OAuth2InvalidCredentials)?;
        match Argon2::default().verify_password(plain.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(SaTokenError::InternalError(format!(
                "verify client secret failed: {e}"
            ))),
        }
    }
}

impl std::fmt::Debug for ClientSecretHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientSecretHasher { .. }")
    }
}
