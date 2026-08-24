// Author: 金书记 | Author: Jin Shuji
//! PKCE (RFC 7636): S256 and plain.
//! PKCE（RFC 7636）：S256 与 plain。

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{SaTokenError, SaTokenResult};
use crate::http_basic::ct_eq;

/// code_challenge_method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeChallengeMethod {
    /// SHA-256 then URL-safe Base64 (no pad). Recommended.
    /// SHA-256 后 URL-safe Base64（无填充）。推荐。
    S256,
    /// Verifier equals challenge. Disallowed for public clients.
    /// verifier 等于 challenge。公共客户端禁止。
    Plain,
}

/// Challenge stored on the authorization code.
/// 存在授权码上的挑战。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkceChallenge {
    /// Challenge string from the client.
    /// 客户端提交的 challenge 串。
    pub code_challenge: String,
    /// Challenge method (S256 / plain).
    /// 挑战方法（S256 / plain）。
    pub code_challenge_method: CodeChallengeMethod,
}

impl PkceChallenge {
    /// Build an S256 challenge from a code_verifier.
    /// 由 code_verifier 构造 S256 challenge。
    pub fn from_verifier_s256(code_verifier: &str) -> SaTokenResult<Self> {
        Self::validate_verifier_len(code_verifier)?;
        let digest = Sha256::digest(code_verifier.as_bytes());
        Ok(Self {
            code_challenge: URL_SAFE_NO_PAD.encode(digest),
            code_challenge_method: CodeChallengeMethod::S256,
        })
    }

    fn validate_verifier_len(code_verifier: &str) -> SaTokenResult<()> {
        if !(43..=128).contains(&code_verifier.len()) {
            return Err(SaTokenError::OAuth2PkceMismatch);
        }
        Ok(())
    }

    /// Verify token-endpoint `code_verifier`.
    /// 校验 token 端提交的 `code_verifier`。
    pub fn verify(&self, code_verifier: &str) -> SaTokenResult<()> {
        Self::validate_verifier_len(code_verifier)?;
        let computed = match self.code_challenge_method {
            CodeChallengeMethod::S256 => {
                let digest = Sha256::digest(code_verifier.as_bytes());
                URL_SAFE_NO_PAD.encode(digest)
            }
            CodeChallengeMethod::Plain => code_verifier.to_string(),
        };
        if ct_eq(computed.as_bytes(), self.code_challenge.as_bytes()) {
            Ok(())
        } else {
            Err(SaTokenError::OAuth2PkceMismatch)
        }
    }
}
