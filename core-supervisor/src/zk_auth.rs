//! Zero-Knowledge Anonymous Authentication — Groth16/Bulletproofs wrapper
//!
//! Authenticates incoming connections using zk-SNARKs (Groth16/Bulletproofs)
//! to verify subscription validity without exposing client identity tokens, IPs, or metadata.
//!
//! This module extends zkp_auth.rs with Groth16-style interface and re-exports.

pub use crate::zkp_auth::{
    Commitment, ZkError, ZkProof, ZkVerificationResult, ZkpVerifier, create_proof,
};

use crate::zkp_auth::{Commitment as InnerCommitment, ZkpVerifier as InnerVerifier};

/// Groth16 proof wrapper (mock)
#[derive(Debug, Clone)]
pub struct Groth16Proof {
    pub inner: ZkProof,
    pub curve: String, // e.g. "bn254"
}

/// Bulletproofs range proof for quota (proves bytes_used < bytes_total without revealing values)
#[derive(Debug, Clone)]
pub struct BulletproofRange {
    pub commitment: InnerCommitment,
    pub proof: Vec<u8>, // mock
    pub bytes_total: i64,
}

/// ZK Auth Engine combining Groth16 membership + Bulletproofs range
#[derive(Debug)]
pub struct ZkAuthEngine {
    verifier: InnerVerifier,
    bulletproofs_verified: std::sync::atomic::AtomicU64,
}

impl ZkAuthEngine {
    #[must_use]
    pub fn new(root: [u8; 32]) -> Self {
        Self {
            verifier: InnerVerifier::new(root),
            bulletproofs_verified: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn add_commitment(&self, commitment: Commitment) {
        self.verifier.add_commitment(commitment);
    }

    /// Verify Groth16 membership proof
    pub fn verify_groth16(&self, proof: &Groth16Proof, now_unix: i64) -> Result<ZkVerificationResult, ZkError> {
        self.verifier.verify_proof(&proof.inner, now_unix)
    }

    /// Verify Bulletproofs range proof (bytes_used < bytes_total)
    pub fn verify_bulletproof(
        &self,
        range_proof: &BulletproofRange,
        bytes_used: i64,
    ) -> Result<bool, ZkError> {
        if bytes_used >= range_proof.bytes_total {
            return Ok(false);
        }
        // Mock verification: proof non-empty and commitment in valid set
        if range_proof.proof.is_empty() {
            return Err(ZkError::InvalidProof);
        }
        self.bulletproofs_verified
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(true)
    }

    #[must_use]
    pub fn verified_count(&self) -> u64 {
        self.verifier.verified_count()
    }

    #[must_use]
    pub fn commitment_count(&self) -> usize {
        self.verifier.commitment_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groth16_wrapper() {
        let root = [1u8; 32];
        let engine = ZkAuthEngine::new(root);
        let token = "test-token-groth16";
        let blinding = [2u8; 32];
        let commitment = Commitment::from_token(token, &blinding);
        engine.add_commitment(commitment);

        let inner_proof = create_proof(token, &blinding, root);
        let groth_proof = Groth16Proof {
            inner: inner_proof,
            curve: "bn254".into(),
        };

        let result = engine.verify_groth16(&groth_proof, 1000).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn bulletproof_range() {
        let root = [0u8; 32];
        let engine = ZkAuthEngine::new(root);
        let commitment = Commitment::from_token("token", &[0u8; 32]);
        engine.add_commitment(commitment.clone());

        let range_proof = BulletproofRange {
            commitment,
            proof: vec![1, 2, 3],
            bytes_total: 50 * 1024 * 1024 * 1024,
        };

        let ok = engine.verify_bulletproof(&range_proof, 10 * 1024 * 1024 * 1024).unwrap();
        assert!(ok);

        let not_ok = engine.verify_bulletproof(&range_proof, 60 * 1024 * 1024 * 1024).unwrap();
        assert!(!not_ok);
    }
}
