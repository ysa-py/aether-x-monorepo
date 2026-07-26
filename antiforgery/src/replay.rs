//! Replay protection.
//!
//! Two complementary mechanisms:
//!
//!   - [`ReplayGuard`]: rejects a nonce that has already been seen within its
//!     TTL window. Used on every privileged action (token refresh, policy push)
//!     so a captured request cannot be replayed.
//!   - [`RefreshVerifier`]: verifies an HMAC-tagged refresh token whose key
//!     rotates, accepting BOTH the current and the immediately-previous key so
//!     a rotation does not invalidate in-flight clients. The tag covers
//!     `token_id || nonce || timestamp`; the timestamp must be within `skew` of
//!     `now`, bounding the replay window independently of nonce storage.

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{AntiForgeryError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Rejects reused nonces within a TTL window. `now` is unix milliseconds so the
/// guard is fully deterministic and testable (no wall clock inside).
#[derive(Debug, Clone)]
pub struct ReplayGuard {
    seen: HashMap<String, i64>,
    ttl_ms: i64,
}

impl ReplayGuard {
    /// Construct with a TTL (milliseconds) for remembering nonces.
    pub fn new(ttl_ms: i64) -> Self {
        Self {
            seen: HashMap::new(),
            ttl_ms: ttl_ms.max(1),
        }
    }

    /// Record `nonce` if unseen (and not expired). Returns `Err(Replay)` if the
    /// nonce is currently live. Also opportunistically prunes expired entries.
    pub fn check_and_record(&mut self, nonce: &str, now_unix_ms: i64) -> Result<()> {
        self.prune(now_unix_ms);
        if let Some(&expiry) = self.seen.get(nonce) {
            if expiry > now_unix_ms {
                return Err(AntiForgeryError::Replay);
            }
        }
        self.seen
            .insert(nonce.to_string(), now_unix_ms + self.ttl_ms);
        Ok(())
    }

    /// Drop entries whose TTL has elapsed.
    pub fn prune(&mut self, now_unix_ms: i64) {
        self.seen.retain(|_, expiry| *expiry > now_unix_ms);
    }

    /// Number of currently-tracked nonces.
    pub fn tracked(&self) -> usize {
        self.seen.len()
    }
}

/// Verifies rotating HMAC refresh tokens. Holds the current key and optionally
/// the previous one to allow seamless rotation.
#[derive(Debug, Clone)]
pub struct RefreshVerifier {
    current_key: Vec<u8>,
    previous_key: Option<Vec<u8>>,
    skew_ms: i64,
}

impl RefreshVerifier {
    /// Construct with the current key and a clock-skew tolerance (milliseconds).
    pub fn new(current_key: Vec<u8>, skew_ms: i64) -> Self {
        Self {
            current_key,
            previous_key: None,
            skew_ms: skew_ms.max(0),
        }
    }

    /// Rotate to a new key, demoting the current key to "previous". Both remain
    /// accepted until the next rotation.
    pub fn rotate(&mut self, new_key: Vec<u8>) {
        self.previous_key = Some(std::mem::replace(&mut self.current_key, new_key));
    }

    /// Verify `(token_id, nonce, timestamp_ms, tag)` against current or previous
    /// key, AND require the timestamp within `skew` of `now`.
    pub fn verify(
        &self,
        token_id: &str,
        nonce: &str,
        timestamp_ms: i64,
        tag: &[u8],
        now_unix_ms: i64,
    ) -> Result<()> {
        if (now_unix_ms - timestamp_ms).abs() > self.skew_ms {
            return Err(AntiForgeryError::StaleRefresh);
        }
        let msg = refresh_message(token_id, nonce, timestamp_ms);
        if hmac_matches(&self.current_key, &msg, tag) {
            return Ok(());
        }
        if let Some(prev) = &self.previous_key {
            if hmac_matches(prev, &msg, tag) {
                return Ok(());
            }
        }
        Err(AntiForgeryError::BadHmac)
    }
}

fn hmac_matches(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(msg);
    mac.verify_slice(tag).is_ok()
}

/// Compute the HMAC tag for a refresh attempt with `key`.
pub fn refresh_tag(key: &[u8], token_id: &str, nonce: &str, timestamp_ms: i64) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&refresh_message(token_id, nonce, timestamp_ms));
    mac.finalize().into_bytes().to_vec()
}

fn refresh_message(token_id: &str, nonce: &str, timestamp_ms: i64) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(token_id.as_bytes());
    m.push(0); // separator byte (0x00 cannot appear in normal token ids/nonces)
    m.extend_from_slice(nonce.as_bytes());
    m.push(0);
    m.extend_from_slice(&timestamp_ms.to_be_bytes());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_rejects_replay_within_ttl() {
        let mut g = ReplayGuard::new(1000);
        assert!(g.check_and_record("n1", 0).is_ok());
        assert!(matches!(
            g.check_and_record("n1", 500),
            Err(AntiForgeryError::Replay)
        ));
    }

    #[test]
    fn guard_accepts_after_ttl_and_prunes() {
        let mut g = ReplayGuard::new(1000);
        assert!(g.check_and_record("n1", 0).is_ok());
        // After TTL has elapsed, the same nonce is acceptable again.
        assert!(g.check_and_record("n1", 2000).is_ok());
        assert_eq!(g.tracked(), 1); // pruned the old entry
    }

    #[test]
    fn refresh_roundtrip_and_rotation() {
        let k1 = b"key-current-verysecret".to_vec();
        let mut v = RefreshVerifier::new(k1.clone(), 5_000);
        let now = 10_000_000;
        let tag = refresh_tag(&k1, "tok", "nonce", now);
        assert!(v.verify("tok", "nonce", now, &tag, now).is_ok());
        // Wrong tag rejected.
        assert!(matches!(
            v.verify("tok", "nonce", now, &[0u8; 32], now),
            Err(AntiForgeryError::BadHmac)
        ));
        // Rotate: tag under k1 must STILL verify (previous key accepted).
        let k2 = b"key-new-verysecret-xxxx".to_vec();
        v.rotate(k2.clone());
        assert!(v.verify("tok", "nonce", now, &tag, now).is_ok());
        // New tag under k2 verifies.
        let tag2 = refresh_tag(&k2, "tok", "nonce2", now);
        assert!(v.verify("tok", "nonce2", now, &tag2, now).is_ok());
    }

    #[test]
    fn refresh_rejects_stale_timestamp() {
        let k = b"k".to_vec();
        let v = RefreshVerifier::new(k.clone(), 1_000);
        let now = 10_000_000;
        let tag = refresh_tag(&k, "t", "n", now - 60_000);
        assert!(matches!(
            v.verify("t", "n", now - 60_000, &tag, now),
            Err(AntiForgeryError::StaleRefresh)
        ));
    }
}
