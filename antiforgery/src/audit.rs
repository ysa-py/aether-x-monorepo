//! Tamper-evident, hash-chained audit log.
//!
//! Every subscription mutation (creation, plan change, expiry extension, quota
//! reset, admin action) is appended as a [`Record`]. Each record's hash is
//! `SHA-256(seq || prev_hash || payload)`, chaining it to the previous record.
//! This makes any retroactive edit cryptographically detectable: altering a
//! payload (or backdating it) invalidates that record's hash and every hash
//! after it. It is conceptually a degenerate Merkle tree (a single chain).
//!
//! This mirrors the certificate-transparency / hash-chaining idea from the
//! specification, but WITHOUT an external blockchain — the chain is the proof.

use sha2::{Digest, Sha256};

use crate::error::{AntiForgeryError, Result};

/// One append-only record. `payload` is the opaque, signed/serialized mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Monotonic sequence number (0-based).
    pub seq: u64,
    /// The opaque mutation payload (e.g. a signed token, a JSON action).
    pub payload: Vec<u8>,
    /// Hash of the previous record; all-zero for the genesis record.
    pub prev_hash: [u8; 32],
    /// `SHA-256(seq_le || prev_hash || payload)`.
    pub hash: [u8; 32],
}

/// Compute the record hash for given (seq, prev_hash, payload).
pub fn record_hash(seq: u64, prev_hash: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(seq.to_le_bytes());
    h.update(prev_hash);
    h.update(payload);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// An append-only hash chain.
#[derive(Debug, Default, Clone)]
pub struct AuditLog {
    records: Vec<Record>,
}

impl AuditLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconstruct a log from a stored set of records (e.g. loaded from a DB).
    /// Does NOT re-verify; call [`AuditLog::verify`] afterwards to check
    /// integrity before trusting it.
    pub fn from_records(records: Vec<Record>) -> Self {
        Self { records }
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The hash of the most recent record (the "root"), or all-zeros if empty.
    pub fn root_hash(&self) -> [u8; 32] {
        self.records.last().map_or([0u8; 32], |r| r.hash)
    }

    /// Append a mutation payload, returning the new record's sequence number.
    pub fn append(&mut self, payload: impl Into<Vec<u8>>) -> u64 {
        let payload: Vec<u8> = payload.into();
        let seq = self.records.len() as u64;
        let prev_hash = self.root_hash();
        let hash = record_hash(seq, &prev_hash, &payload);
        self.records.push(Record {
            seq,
            payload,
            prev_hash,
            hash,
        });
        seq
    }

    /// Read-only access to the records (e.g. for external replication/storage).
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Compute the Merkle root over all record payloads in O(n). This is a
    /// compact, publicly-publishable commitment to the ENTIRE log (whereas
    /// [`AuditLog::root_hash`] commits only to the last chain record). Pairs
    /// with [`crate::merkle`] for O(log n) inclusion proofs. Returns all-zeros
    /// for an empty log. (Additive; does not change the hash chain.)
    pub fn merkle_root(&self) -> [u8; 32] {
        let payloads: Vec<Vec<u8>> = self.records.iter().map(|r| r.payload.clone()).collect();
        crate::merkle::MerkleTree::from_leaves(&payloads)
            .root()
            .unwrap_or([0u8; 32])
    }

    /// Verify the entire chain. Returns the sequence number of the FIRST record
    /// whose hash does not match recomputation, or `Ok(())` if the chain is
    /// intact. A tampered payload, a swapped record, or a deleted record all
    /// surface here.
    pub fn verify(&self) -> Result<()> {
        let mut prev = [0u8; 32];
        for r in &self.records {
            if r.prev_hash != prev {
                return Err(AntiForgeryError::AuditTamper(r.seq));
            }
            let recomputed = record_hash(r.seq, &r.prev_hash, &r.payload);
            if recomputed != r.hash {
                return Err(AntiForgeryError::AuditTamper(r.seq));
            }
            prev = r.hash;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_grows_and_verifies() {
        let mut log = AuditLog::new();
        assert!(log.is_empty());
        let s0 = log.append(b"create sub-1");
        let s1 = log.append(b"extend sub-1 +30d");
        let s2 = log.append(b"reset quota sub-1");
        assert_eq!([s0, s1, s2], [0, 1, 2]);
        assert!(log.verify().is_ok());
    }

    #[test]
    fn tampering_payload_is_detected() {
        let mut log = AuditLog::new();
        log.append(b"create");
        log.append(b"extend");
        log.append(b"reset");
        assert!(log.verify().is_ok());

        // Mutate the first record's stored payload in place.
        log.records[0].payload[0] ^= 0x01;
        match log.verify() {
            Err(AntiForgeryError::AuditTamper(seq)) => assert_eq!(seq, 0),
            other => panic!("expected tamper at 0, got {other:?}"),
        }
    }

    #[test]
    fn tampering_a_hash_is_detected() {
        let mut log = AuditLog::new();
        log.append(b"a");
        log.append(b"b");
        // Corrupt the stored hash of record 0; verification recomputes and
        // notices record 0, and the prev_hash link of record 1 also breaks.
        log.records[0].hash[0] ^= 0xff;
        assert!(log.verify().is_err());
    }

    #[test]
    fn root_hash_changes_per_append() {
        let mut log = AuditLog::new();
        let z = log.root_hash();
        log.append(b"x");
        let h1 = log.root_hash();
        log.append(b"y");
        let h2 = log.root_hash();
        assert_ne!(z, h1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn deterministic_hash() {
        // Same inputs -> same hash, across runs.
        let h = record_hash(7, &[0xaa; 32], b"payload");
        let h2 = record_hash(7, &[0xaa; 32], b"payload");
        assert_eq!(h, h2);
    }
}
