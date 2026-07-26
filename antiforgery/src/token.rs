//! Ed25519-signed subscription tokens.
//!
//! A token carries the *authoritative* quota + expiry. Because it is signed by
//! the server's Ed25519 key, a client cannot alter `bytes_used`, `bytes_total`,
//! or `expires_unix` without invalidating the signature. The token format is:
//!
//! ```text
//! base64url(canonical_json(claims) "." base64url(signature_64_bytes))
//! ```
//!
//! The signature is computed over the *exact* JSON bytes embedded in the token,
//! so there is no canonicalization ambiguity between issuer and verifier.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{AntiForgeryError, Result};

/// The signed claims for one subscription. Field order is the canonical order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Stable subscription id.
    pub subscription_id: String,
    /// Owning user id.
    pub user_id: String,
    /// Total quota, bytes.
    pub bytes_total: i64,
    /// Bytes already consumed (server-verified).
    pub bytes_used: i64,
    /// Absolute expiry, unix seconds UTC.
    pub expires_unix: i64,
    /// Issuance time, unix seconds UTC.
    pub issued_unix: i64,
    /// Unique-per-issue nonce (defeats token replay at the verifier).
    pub nonce: String,
}

impl Claims {
    /// Remaining bytes, floored at zero.
    pub fn bytes_remaining(&self) -> i64 {
        (self.bytes_total - self.bytes_used).max(0)
    }

    /// Seconds remaining until expiry, floored at zero.
    pub fn secs_remaining(&self, now_unix: i64) -> i64 {
        (self.expires_unix - now_unix).max(0)
    }

    /// True if the token is valid right now: not expired AND quota remaining.
    pub fn is_live(&self, now_unix: i64) -> bool {
        !self.is_expired(now_unix) && self.bytes_remaining() > 0
    }

    /// True if past expiry.
    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_unix
    }
}

/// Sign `claims` with `signing_key`, returning the compact token string.
pub fn issue(signing_key: &SigningKey, claims: &Claims) -> Result<String> {
    let json = serde_json::to_vec(claims)?;
    let sig: Signature = signing_key.sign(&json);
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&json),
        URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    ))
}

/// Verify `token` against `verifying_key` and return the parsed [`Claims`].
///
/// This checks ONLY the signature. Callers must additionally check expiry/quota
/// via [`Claims::is_live`] at the moment of use.
pub fn verify(verifying_key: &VerifyingKey, token: &str) -> Result<Claims> {
    let (json_b64, sig_b64) = token
        .split_once('.')
        .ok_or_else(|| AntiForgeryError::Malformed("missing '.' separator".into()))?;
    let json = URL_SAFE_NO_PAD.decode(json_b64)?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AntiForgeryError::Malformed("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(&json, &sig)
        .map_err(|_| AntiForgeryError::BadSignature)?;

    Ok(serde_json::from_slice(&json)?)
}

/// Convenience: generate a fresh signing key using the OS CSPRNG.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Owning wrapper around a [`SigningKey`] that bundles the common operations
/// (issue, public key). Handy for services that hold a long-lived key.
#[derive(Debug, Clone)]
pub struct TokenSigner {
    sk: SigningKey,
}

impl TokenSigner {
    /// Wrap an existing signing key.
    #[must_use]
    pub fn new(sk: SigningKey) -> Self {
        Self { sk }
    }

    /// Generate a fresh signer with a random key.
    ///
    /// Intended for tests and explicitly enabled local development only. A
    /// service deployment must load a stable secret so issued subscriptions
    /// remain verifiable after a restart.
    #[must_use]
    pub fn generate() -> Self {
        Self::new(generate_signing_key())
    }

    /// Build a stable signer from exactly 32 bytes of private seed material.
    ///
    /// Callers own retrieval and zeroization policy for the secret. This
    /// wrapper never serializes or exposes the private key.
    #[must_use]
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        Self::new(SigningKey::from_bytes(&secret))
    }

    /// The verifying (public) key for this signer.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.sk.verifying_key()
    }

    /// The verifying key as raw bytes (32).
    #[must_use]
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.sk.verifying_key().to_bytes().to_vec()
    }

    /// Sign `claims`, returning the compact token string.
    pub fn issue(&self, claims: &Claims) -> Result<String> {
        issue(&self.sk, claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims(nonce: &str) -> Claims {
        Claims {
            subscription_id: "sub-1".into(),
            user_id: "u-1".into(),
            bytes_total: 1_000_000_000,
            bytes_used: 250_000_000,
            expires_unix: 2_000_000_000,
            issued_unix: 1_999_000_000,
            nonce: nonce.into(),
        }
    }

    #[test]
    fn roundtrip_verifies() {
        let sk = generate_signing_key();
        let vk = sk.verifying_key();
        let claims = sample_claims("n1");
        let tok = issue(&sk, &claims).unwrap();
        let back = verify(&vk, &tok).unwrap();
        assert_eq!(back, claims);
    }

    #[test]
    fn wrong_key_rejects() {
        let sk1 = generate_signing_key();
        let sk2 = generate_signing_key();
        let tok = issue(&sk1, &sample_claims("n2")).unwrap();
        assert!(matches!(
            verify(&sk2.verifying_key(), &tok),
            Err(AntiForgeryError::BadSignature)
        ));
    }

    #[test]
    fn tampered_payload_rejects() {
        let sk = generate_signing_key();
        let vk = sk.verifying_key();
        let tok = issue(&sk, &sample_claims("n3")).unwrap();
        // Flip a byte in the embedded JSON (keeping the original signature) and
        // confirm verification fails — without any unsafe.
        let (json_b64, sig_b64) = tok.split_once('.').unwrap();
        let mut json = URL_SAFE_NO_PAD.decode(json_b64).unwrap();
        json[0] ^= 0x01;
        let tampered = format!("{}.{}", URL_SAFE_NO_PAD.encode(&json), sig_b64);
        assert!(verify(&vk, &tampered).is_err());
    }

    #[test]
    fn quota_and_expiry_helpers() {
        let c = sample_claims("n4");
        assert_eq!(c.bytes_remaining(), 750_000_000);
        assert!(c.is_live(1_999_500_000));
        assert!(!c.is_expired(1_999_500_000));
        assert!(c.is_expired(2_000_000_001));
        let exhausted = Claims {
            bytes_used: 1_000_000_000,
            ..c.clone()
        };
        assert!(!exhausted.is_live(1_999_500_000));
    }
}
