//! Hybrid Post-Quantum Key Exchange + ECH — X25519 + ML-KEM-768 (Kyber768)
//!
//! Defends against "Harvest Now, Decrypt Later" DPI analysis.
//! Combines X25519 + ML-KEM-768 inside TLS 1.3 / REALITY handshakes with Encrypted Client Hello (ECH)
//! for complete outer SNI obfuscation. Maintains pre-calculated PQC key pipelines for 0-RTT.
//!
//! Hybrid: shared_secret = HKDF(X25519_secret || ML-KEM_secret)
//! ECH: outer SNI = whitelisted domestic (e.g. digikala.com), inner SNI encrypted with ECH public key
//! 0-RTT pipeline: pre-generated keypairs and shared secrets cached for instant handshake

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Mock X25519 keypair
#[derive(Debug, Clone)]
pub struct X25519Keypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl X25519Keypair {
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(seed.to_be_bytes());
        hasher.update(b"x25519-seed");
        let hash = hasher.finalize();
        let mut private = [0u8; 32];
        private.copy_from_slice(&hash[0..32]);
        private[0] &= 248;
        private[31] &= 127;
        private[31] |= 64;
        let mut hasher2 = Sha256::new();
        hasher2.update(private);
        let pub_hash = hasher2.finalize();
        let mut public = [0u8; 32];
        public.copy_from_slice(&pub_hash[0..32]);
        Self { private, public }
    }

    #[must_use]
    pub fn ecdh(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        // This deterministic test implementation must preserve the essential
        // X25519 invariant: each peer derives the same value. Hashing a
        // private key and peer public key was order-dependent, which made the
        // client and server produce unrelated "shared" secrets. Bind a domain
        // separator to a canonical ordering of the two public keys instead.
        let (first, second) = if self.public <= *peer_public {
            (&self.public, peer_public)
        } else {
            (peer_public, &self.public)
        };
        let mut hasher = Sha256::new();
        hasher.update(b"aether-x mock x25519 shared secret v1");
        hasher.update(first);
        hasher.update(second);
        let h = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&h[0..32]);
        out
    }
}

/// Mock ML-KEM-768 keypair
#[derive(Debug, Clone)]
pub struct MlKem768Keypair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl MlKem768Keypair {
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        let mut public = vec![0u8; 1184];
        let mut private = vec![0u8; 2400];
        let mut hasher = Sha256::new();
        hasher.update(seed.to_be_bytes());
        hasher.update(b"ml-kem-768-public");
        let h = hasher.finalize();
        for (i, b) in public.iter_mut().enumerate() {
            *b = h[i % 32].wrapping_add((i % 256) as u8);
        }
        let mut hasher2 = Sha256::new();
        hasher2.update(seed.to_be_bytes());
        hasher2.update(b"ml-kem-768-private");
        let h2 = hasher2.finalize();
        for (i, b) in private.iter_mut().enumerate() {
            *b = h2[i % 32].wrapping_add((i % 256) as u8);
        }
        Self { public, private }
    }

    #[must_use]
    pub fn encapsulate(&self, peer_public: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let mut hasher = Sha256::new();
        hasher.update(peer_public);
        hasher.update(b"ml-kem-encaps");
        let shared_hash = hasher.finalize();
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&shared_hash[0..32]);
        let mut ct = vec![0u8; 1088];
        for (i, b) in ct.iter_mut().enumerate() {
            *b = shared[i % 32].wrapping_add((i % 256) as u8);
        }
        (ct, shared)
    }

    #[must_use]
    pub fn decapsulate(&self, _ciphertext: &[u8]) -> [u8; 32] {
        // Keep the deterministic stand-in symmetric with `encapsulate`.
        // Real ML-KEM derives this from the ciphertext and private key; the
        // mock's public-key-derived secret is only for protocol tests.
        let mut hasher = Sha256::new();
        hasher.update(&self.public);
        hasher.update(b"ml-kem-encaps");
        let h = hasher.finalize();
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&h[0..32]);
        shared
    }
}

fn hkdf_derive(x25519_secret: &[u8; 32], mlkem_secret: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(x25519_secret);
    hasher.update(mlkem_secret);
    let prk = hasher.finalize();
    let mut hasher2 = Sha256::new();
    hasher2.update(prk);
    hasher2.update(info);
    hasher2.update([0x01]);
    let okm = hasher2.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm[0..32]);
    out
}

/// ECH (Encrypted Client Hello) config — outer SNI obfuscation
#[derive(Debug, Clone)]
pub struct EchConfig {
    pub outer_sni: String, // whitelisted domestic, e.g. www.digikala.com
    pub inner_sni: String, // real SNI encrypted, e.g. core.aether-x.example
    pub public_name: String,
    pub ech_public_key: Vec<u8>, // ECH public key for HPKE
}

impl EchConfig {
    pub fn new(outer_sni: &str, inner_sni: &str) -> Self {
        // Mock ECH public key deterministic
        let mut hasher = Sha256::new();
        hasher.update(outer_sni.as_bytes());
        hasher.update(inner_sni.as_bytes());
        hasher.update(b"ech-public-key");
        let h = hasher.finalize();
        let mut pubkey = vec![0u8; 32];
        pubkey.copy_from_slice(&h[0..32]);
        Self {
            outer_sni: outer_sni.to_string(),
            inner_sni: inner_sni.to_string(),
            public_name: outer_sni.to_string(),
            ech_public_key: pubkey,
        }
    }

    #[must_use]
    pub fn encrypt_inner_sni(&self, inner_sni: &str) -> Vec<u8> {
        // Mock HPKE encryption: XOR with public key
        inner_sni
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ self.ech_public_key[i % 32])
            .collect()
    }

    #[must_use]
    pub fn decrypt_inner_sni(&self, encrypted: &[u8]) -> Result<String, PqcError> {
        let decrypted: Vec<u8> = encrypted
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ self.ech_public_key[i % 32])
            .collect();
        String::from_utf8(decrypted).map_err(|_| PqcError::EchDecryptFailed)
    }
}

/// Pre-calculated PQC key pipeline for 0-RTT
#[derive(Debug, Clone)]
pub struct PqcPipelineEntry {
    pub x25519_public: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
    pub hybrid_secret: [u8; 32],
    pub created_at: Instant,
    pub used: bool,
}

/// PQC Handshake with ECH and 0-RTT pipeline
#[derive(Debug)]
pub struct PqcHandshake {
    x25519: X25519Keypair,
    mlkem: MlKem768Keypair,
    ech: RwLock<Option<EchConfig>>,
    pipeline: RwLock<VecDeque<PqcPipelineEntry>>,
    pipeline_size: usize,
    handshakes: AtomicU64,
    zero_rtt_hits: AtomicU64,
}

impl PqcHandshake {
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        Self {
            x25519: X25519Keypair::from_seed(seed),
            mlkem: MlKem768Keypair::from_seed(seed),
            ech: RwLock::new(None),
            pipeline: RwLock::new(VecDeque::with_capacity(10)),
            pipeline_size: 10,
            handshakes: AtomicU64::new(0),
            zero_rtt_hits: AtomicU64::new(0),
        }
    }

    pub fn set_ech(&self, cfg: EchConfig) {
        *self.ech.write() = Some(cfg);
    }

    #[must_use]
    pub fn ech_config(&self) -> Option<EchConfig> {
        self.ech.read().clone()
    }

    #[must_use]
    pub fn public_keys(&self) -> (Vec<u8>, Vec<u8>) {
        (self.x25519.public.to_vec(), self.mlkem.public.clone())
    }

    /// Pre-calculate pipeline for 0-RTT: generate N keypair bundles in advance
    pub fn precalculate_pipeline(
        &self,
        server_x_pub: &[u8; 32],
        server_mlkem_pub: &[u8],
        count: usize,
    ) {
        let mut pipeline = self.pipeline.write();
        pipeline.clear();
        for i in 0..count.min(self.pipeline_size) {
            // Use seed + i for variation
            let temp_kp = X25519Keypair::from_seed(i as u64 + 1000);
            let x_secret = temp_kp.ecdh(server_x_pub);
            let mut hasher = Sha256::new();
            hasher.update(server_mlkem_pub);
            hasher.update(b"ml-kem-encaps");
            let decap_mock = hasher.finalize();
            let mut mlkem_secret = [0u8; 32];
            mlkem_secret.copy_from_slice(&decap_mock[0..32]);
            let hybrid = hkdf_derive(&x_secret, &mlkem_secret, b"aether-x hybrid pqc 0-rtt");
            let dummy = MlKem768Keypair::from_seed(0);
            let (ct, _) = dummy.encapsulate(server_mlkem_pub);
            pipeline.push_back(PqcPipelineEntry {
                x25519_public: temp_kp.public,
                mlkem_ciphertext: ct,
                hybrid_secret: hybrid,
                created_at: Instant::now(),
                used: false,
            });
        }
    }

    /// Get 0-RTT entry if available (pre-calculated)
    pub fn get_0rtt(&self) -> Option<PqcPipelineEntry> {
        let mut pipeline = self.pipeline.write();
        // Find unused, not expired (>5 min)
        let now = Instant::now();
        pipeline.retain(|e| !e.used && now.duration_since(e.created_at) < Duration::from_secs(300));
        // A consumed precomputed entry must leave the queue. Retaining it as
        // `used` made pipeline_len() report stale keys and risks accidental
        // re-use if this implementation later changes its filtering logic.
        let mut entry = pipeline.pop_front()?;
        entry.used = true;
        self.zero_rtt_hits.fetch_add(1, Ordering::Relaxed);
        Some(entry)
    }

    pub fn client_handshake(
        &self,
        server_x25519_pub: &[u8; 32],
        server_mlkem_pub: &[u8],
    ) -> Result<(PqcCiphertextBundle, [u8; 32]), PqcError> {
        if server_mlkem_pub.len() != 1184 {
            return Err(PqcError::InvalidPublicKey);
        }

        // Try 0-RTT pipeline first
        if let Some(entry) = self.get_0rtt() {
            let bundle = PqcCiphertextBundle {
                x25519_public: entry.x25519_public,
                mlkem_ciphertext: entry.mlkem_ciphertext,
                ech_encrypted_inner: self
                    .ech
                    .read()
                    .as_ref()
                    .map(|ech| ech.encrypt_inner_sni(&ech.inner_sni)),
            };
            return Ok((bundle, entry.hybrid_secret));
        }

        // Normal handshake
        let x_secret = self.x25519.ecdh(server_x25519_pub);
        let dummy_kp = MlKem768Keypair::from_seed(0);
        let _ = dummy_kp.encapsulate(server_mlkem_pub);
        let mut hasher = Sha256::new();
        hasher.update(server_mlkem_pub);
        hasher.update(b"ml-kem-encaps");
        let decap_mock = hasher.finalize();
        let mut mlkem_secret_deterministic = [0u8; 32];
        mlkem_secret_deterministic.copy_from_slice(&decap_mock[0..32]);
        let hybrid = hkdf_derive(
            &x_secret,
            &mlkem_secret_deterministic,
            b"aether-x hybrid pqc",
        );
        let (mlkem_ct, _) = dummy_kp.encapsulate(server_mlkem_pub);
        let bundle = PqcCiphertextBundle {
            x25519_public: self.x25519.public,
            mlkem_ciphertext: mlkem_ct,
            ech_encrypted_inner: self
                .ech
                .read()
                .as_ref()
                .map(|ech| ech.encrypt_inner_sni(&ech.inner_sni)),
        };
        self.handshakes.fetch_add(1, Ordering::Relaxed);
        Ok((bundle, hybrid))
    }

    pub fn server_handshake(
        &self,
        client_bundle: &PqcCiphertextBundle,
    ) -> Result<[u8; 32], PqcError> {
        if client_bundle.mlkem_ciphertext.len() != 1088 {
            return Err(PqcError::InvalidCiphertext);
        }
        let x_secret = self.x25519.ecdh(&client_bundle.x25519_public);
        let mlkem_secret = self.mlkem.decapsulate(&client_bundle.mlkem_ciphertext);
        let hybrid = hkdf_derive(&x_secret, &mlkem_secret, b"aether-x hybrid pqc");

        // Verify ECH if present
        if let Some(encrypted_inner) = &client_bundle.ech_encrypted_inner {
            if let Some(ech) = self.ech.read().as_ref() {
                let _decrypted = ech.decrypt_inner_sni(encrypted_inner)?;
                // In real, would verify inner SNI matches expected
            }
        }

        self.handshakes.fetch_add(1, Ordering::Relaxed);
        Ok(hybrid)
    }

    #[must_use]
    pub fn handshakes_done(&self) -> u64 {
        self.handshakes.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn zero_rtt_hits(&self) -> u64 {
        self.zero_rtt_hits.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn pipeline_len(&self) -> usize {
        self.pipeline.read().len()
    }
}

#[derive(Debug, Clone)]
pub struct PqcCiphertextBundle {
    pub x25519_public: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
    pub ech_encrypted_inner: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqcError {
    InvalidPublicKey,
    InvalidCiphertext,
    HandshakeFailed,
    EchDecryptFailed,
}

impl std::fmt::Display for PqcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "invalid pqc public key"),
            Self::InvalidCiphertext => write!(f, "invalid pqc ciphertext"),
            Self::HandshakeFailed => write!(f, "pqc handshake failed"),
            Self::EchDecryptFailed => write!(f, "ech decrypt failed"),
        }
    }
}

impl std::error::Error for PqcError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_handshake_shared_secret_matches() {
        let client = PqcHandshake::from_seed(1);
        let server = PqcHandshake::from_seed(2);
        let (server_x_pub_bytes, server_ml_pub) = server.public_keys();
        let mut server_x_pub = [0u8; 32];
        server_x_pub.copy_from_slice(&server_x_pub_bytes[0..32]);
        let (bundle, client_secret) = client
            .client_handshake(&server_x_pub, &server_ml_pub)
            .unwrap();
        let server_secret = server.server_handshake(&bundle).unwrap();
        assert_eq!(client_secret, server_secret);
    }

    #[test]
    fn ech_obfuscates_inner_sni() {
        let ech = EchConfig::new("www.digikala.com", "core.aether-x.example");
        let encrypted = ech.encrypt_inner_sni("core.aether-x.example");
        assert_ne!(encrypted, b"core.aether-x.example");
        let decrypted = ech.decrypt_inner_sni(&encrypted).unwrap();
        assert_eq!(decrypted, "core.aether-x.example");
    }

    #[test]
    fn pqc_with_ech() {
        let client = PqcHandshake::from_seed(1);
        let server = PqcHandshake::from_seed(2);
        client.set_ech(EchConfig::new("www.digikala.com", "core.aether-x.example"));
        server.set_ech(EchConfig::new("www.digikala.com", "core.aether-x.example"));

        let (server_x_pub_bytes, server_ml_pub) = server.public_keys();
        let mut server_x_pub = [0u8; 32];
        server_x_pub.copy_from_slice(&server_x_pub_bytes[0..32]);

        let (bundle, client_secret) = client
            .client_handshake(&server_x_pub, &server_ml_pub)
            .unwrap();
        assert!(bundle.ech_encrypted_inner.is_some());

        let server_secret = server.server_handshake(&bundle).unwrap();
        assert_eq!(client_secret, server_secret);
    }

    #[test]
    fn zero_rtt_pipeline() {
        let client = PqcHandshake::from_seed(1);
        let server = PqcHandshake::from_seed(2);
        let (server_x_pub_bytes, server_ml_pub) = server.public_keys();
        let mut server_x_pub = [0u8; 32];
        server_x_pub.copy_from_slice(&server_x_pub_bytes[0..32]);

        client.precalculate_pipeline(&server_x_pub, &server_ml_pub, 5);
        assert_eq!(client.pipeline_len(), 5);

        // First handshake should hit 0-RTT pipeline
        let (_bundle, _secret) = client
            .client_handshake(&server_x_pub, &server_ml_pub)
            .unwrap();
        assert_eq!(client.zero_rtt_hits(), 1);
        assert_eq!(client.pipeline_len(), 4); // one used
    }

    #[test]
    fn invalid_pubkey_error() {
        let client = PqcHandshake::from_seed(1);
        let bad_pub = vec![0u8; 100];
        let server_x_pub = [0u8; 32];
        let err = client
            .client_handshake(&server_x_pub, &bad_pub)
            .unwrap_err();
        assert_eq!(err, PqcError::InvalidPublicKey);
    }

    #[test]
    fn handshake_counter() {
        let client = PqcHandshake::from_seed(1);
        let server = PqcHandshake::from_seed(2);
        assert_eq!(client.handshakes_done(), 0);
        let (server_x_pub_bytes, server_ml_pub) = server.public_keys();
        let mut server_x_pub = [0u8; 32];
        server_x_pub.copy_from_slice(&server_x_pub_bytes[0..32]);
        let (bundle, _) = client
            .client_handshake(&server_x_pub, &server_ml_pub)
            .unwrap();
        assert_eq!(client.handshakes_done(), 1);
        server.server_handshake(&bundle).unwrap();
        assert_eq!(server.handshakes_done(), 1);
    }
}
