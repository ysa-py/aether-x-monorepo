//! Error model for the anti-forgery core.

use thiserror::Error;

/// Every fallible anti-forgery operation returns [`Result<_, AntiForgeryError>`].
#[derive(Debug, Error)]
pub enum AntiForgeryError {
    /// The token's signature did not verify against the provided public key.
    #[error("invalid signature")]
    BadSignature,

    /// The token bytes were malformed (bad base64, missing '.', bad JSON).
    #[error("malformed token: {0}")]
    Malformed(String),

    /// The token's quota is exhausted.
    #[error("quota exhausted")]
    QuotaExhausted,

    /// The token has passed its expiry.
    #[error("expired")]
    Expired,

    /// A nonce was reused within its TTL window.
    #[error("replay detected for nonce")]
    Replay,

    /// A refresh timestamp was outside the allowed skew window.
    #[error("refresh timestamp out of skew window")]
    StaleRefresh,

    /// Too many concurrent devices for a subscription.
    #[error("concurrent device limit reached")]
    DeviceLimit,

    /// The audit log failed an integrity check (tamper detected).
    #[error("audit log integrity failure at entry {0}")]
    AuditTamper(u64),

    /// HMAC verification failed (wrong key or altered message).
    #[error("hmac verification failed")]
    BadHmac,

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    #[error(transparent)]
    Signature(#[from] ed25519_dalek::SignatureError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, AntiForgeryError>;
