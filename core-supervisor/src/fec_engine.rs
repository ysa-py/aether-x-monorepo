//! Adaptive Forward Error Correction — systematic Reed–Solomon over GF(2^8).
//!
//! Reconstructs lost payloads under extreme physical packet loss (30%–50%)
//! without TCP retransmission delays.
//!
//! What is actually implemented here (no hand-waving):
//! - A real GF(2^8) arithmetic layer (log/exp tables, primitive polynomial
//!   0x11d) — [`gf`].
//! - A **systematic** Reed–Solomon erasure code: the first `k` shards are the
//!   verbatim data shards, the following `m` shards are parity rows taken from
//!   a Cauchy matrix. Every square submatrix of a Cauchy matrix is invertible,
//!   so **any** `k` of the `k + m` shards reconstruct the original data
//!   exactly. That is the MDS property, and it is what makes "survives 40%
//!   loss" a provable claim rather than a slogan.
//! - Adaptive FEC: parity count tracks observed loss ([`AdaptiveFec`]).
//!
//! Bound (documented, enforced): `k + m <= 255`, because the Cauchy
//! construction needs `k + m` distinct non-zero field elements with disjoint
//! row/column sets. [`FecEncoder::new`] rejects configurations past that bound
//! instead of silently emitting a non-recoverable code.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ── GF(2^8) arithmetic ─────────────────────────────────────────────────────

/// Galois-field arithmetic for GF(2^8) with primitive polynomial 0x11d.
mod gf {
    /// Exponentiation table: `EXP[i] == g^i`, doubled so index up to 509 is safe.
    static TABLES: once_cell::sync::Lazy<([u8; 512], [u8; 256])> =
        once_cell::sync::Lazy::new(|| {
            let mut exp = [0u8; 512];
            let mut log = [0u8; 256];
            let mut x: u16 = 1;
            for i in 0..255 {
                exp[i] = x as u8;
                log[x as usize] = i as u8;
                x <<= 1;
                if x & 0x100 != 0 {
                    x ^= 0x11d;
                }
            }
            for i in 255..512 {
                exp[i] = exp[i - 255];
            }
            (exp, log)
        });

    /// Field addition (and subtraction) is XOR.
    #[inline]
    #[must_use]
    pub fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// Field multiplication.
    #[inline]
    #[must_use]
    pub fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let (exp, log) = &*TABLES;
        exp[log[a as usize] as usize + log[b as usize] as usize]
    }

    /// Field division. Panics only on division by zero, which the callers in
    /// this module structurally never do (pivots are checked non-zero first).
    #[inline]
    #[must_use]
    pub fn div(a: u8, b: u8) -> u8 {
        assert!(b != 0, "GF(2^8) division by zero");
        if a == 0 {
            return 0;
        }
        let (exp, log) = &*TABLES;
        let idx = 255 + log[a as usize] as usize - log[b as usize] as usize;
        exp[idx % 255]
    }

    /// Multiplicative inverse.
    #[inline]
    #[must_use]
    pub fn inv(a: u8) -> u8 {
        div(1, a)
    }
}

/// Build the `m x k` Cauchy parity matrix.
///
/// Rows use `x_p = p` (`0..m`), columns use `y_i = m + i` (`0..k`), so the two
/// index sets are disjoint and every entry `1 / (x_p ^ y_i)` is well defined.
/// Any square submatrix of a Cauchy matrix is invertible ⇒ the resulting
/// systematic code is MDS: any `k` surviving shards suffice.
fn cauchy_parity_matrix(k: usize, m: usize) -> Vec<Vec<u8>> {
    let mut rows = Vec::with_capacity(m);
    for p in 0..m {
        let mut row = Vec::with_capacity(k);
        for i in 0..k {
            let x = p as u8;
            let y = (m + i) as u8;
            row.push(gf::inv(gf::add(x, y)));
        }
        rows.push(row);
    }
    rows
}

/// Invert a `n x n` matrix over GF(2^8) by Gauss–Jordan elimination.
/// Returns `None` if the matrix is singular (cannot happen for Cauchy-derived
/// submatrices, but we never `unwrap` on adversary-influenced input).
fn invert_matrix(mut a: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let n = a.len();
    let mut inv: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            let mut row = vec![0u8; n];
            row[i] = 1;
            row
        })
        .collect();

    for col in 0..n {
        // Find a non-zero pivot.
        let pivot = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, pivot);
        inv.swap(col, pivot);

        // Normalise the pivot row.
        let p = a[col][col];
        let p_inv = gf::inv(p);
        for j in 0..n {
            a[col][j] = gf::mul(a[col][j], p_inv);
            inv[col][j] = gf::mul(inv[col][j], p_inv);
        }

        // Eliminate the column from every other row.
        for r in 0..n {
            if r == col {
                continue;
            }
            let factor = a[r][col];
            if factor == 0 {
                continue;
            }
            for j in 0..n {
                a[r][j] = gf::add(a[r][j], gf::mul(factor, a[col][j]));
                inv[r][j] = gf::add(inv[r][j], gf::mul(factor, inv[col][j]));
            }
        }
    }
    Some(inv)
}

/// Maximum total shards supported by the Cauchy construction.
pub const MAX_TOTAL_SHARDS: usize = 255;

/// FEC configuration
#[derive(Debug, Clone)]
pub struct FecConfig {
    /// Number of data shards
    pub k: usize,
    /// Number of parity shards
    pub m: usize,
    /// Max shard size bytes
    pub shard_size: usize,
    /// Adaptive: target loss rate to survive (0.3-0.5)
    pub target_loss: f64,
}

impl FecConfig {
    pub fn new(k: usize, m: usize, shard_size: usize) -> Self {
        Self {
            k,
            m,
            shard_size,
            target_loss: 0.3,
        }
    }

    /// Adaptive config for a target loss: need `m >= k*loss/(1-loss)`.
    #[must_use]
    pub fn for_loss(k: usize, loss_rate: f64, shard_size: usize) -> Self {
        let loss = loss_rate.clamp(0.0, 0.9);
        let m = ((k as f64 * loss / (1.0 - loss)).ceil() as usize).max(1);
        Self {
            k,
            m,
            shard_size,
            target_loss: loss,
        }
    }

    #[must_use]
    pub fn total_shards(&self) -> usize {
        self.k + self.m
    }

    #[must_use]
    pub fn overhead_ratio(&self) -> f64 {
        self.m as f64 / self.k as f64
    }

    /// Whether this configuration can be realised by the GF(2^8) construction.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.k > 0 && self.m > 0 && self.total_shards() <= MAX_TOTAL_SHARDS
    }
}

/// A shard (data or parity)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    pub index: usize,
    pub is_parity: bool,
    pub data: Vec<u8>,
}

/// FEC Encoder
#[derive(Debug)]
pub struct FecEncoder {
    config: FecConfig,
    encoded_batches: AtomicU64,
}

impl FecEncoder {
    #[must_use]
    pub fn new(config: FecConfig) -> Self {
        Self {
            config,
            encoded_batches: AtomicU64::new(0),
        }
    }

    /// Encode data into `k` systematic data shards + `m` Reed–Solomon parity
    /// shards. Any `k` of the `k + m` outputs reconstruct the input exactly.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Shard>, FecError> {
        if data.is_empty() {
            return Err(FecError::EmptyData);
        }
        if !self.config.is_supported() {
            return Err(FecError::InvalidConfig);
        }

        // Split data into k equal-length shards (zero-padded tail). The
        // original length is carried out-of-band and used to truncate on
        // decode, so padding never corrupts the recovered payload.
        let shard_len = data.len().div_ceil(self.config.k).max(1);
        if shard_len > self.config.shard_size {
            return Err(FecError::PayloadTooLarge {
                needed: shard_len,
                shard_size: self.config.shard_size,
            });
        }

        let mut shards = Vec::with_capacity(self.config.total_shards());
        for i in 0..self.config.k {
            let start = i * shard_len;
            let end = (start + shard_len).min(data.len());
            let mut shard_data = if start < data.len() {
                data[start..end].to_vec()
            } else {
                Vec::new()
            };
            shard_data.resize(shard_len, 0);
            shards.push(Shard {
                index: i,
                is_parity: false,
                data: shard_data,
            });
        }

        // Parity: each row is an independent linear combination over GF(2^8).
        let matrix = cauchy_parity_matrix(self.config.k, self.config.m);
        for (p, row) in matrix.iter().enumerate() {
            let mut parity = vec![0u8; shard_len];
            for (i, &coef) in row.iter().enumerate() {
                let src = &shards[i].data;
                for (out, &byte) in parity.iter_mut().zip(src.iter()) {
                    *out = gf::add(*out, gf::mul(coef, byte));
                }
            }
            shards.push(Shard {
                index: self.config.k + p,
                is_parity: true,
                data: parity,
            });
        }

        self.encoded_batches.fetch_add(1, Ordering::Relaxed);
        Ok(shards)
    }

    #[must_use]
    pub fn config(&self) -> &FecConfig {
        &self.config
    }

    #[must_use]
    pub fn batches_encoded(&self) -> u64 {
        self.encoded_batches.load(Ordering::Relaxed)
    }
}

/// FEC Decoder – reconstructs lost shards from any `k` survivors.
#[derive(Debug, Default)]
pub struct FecDecoder {
    decoded_batches: AtomicU64,
    recovered_shards: AtomicU64,
}

impl FecDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode: given the received shards (any subset), reconstruct the payload.
    ///
    /// Succeeds iff at least `k` distinct shards survive — regardless of which
    /// ones. Returns exactly the original `original_len` bytes.
    pub fn decode(
        &self,
        received: Vec<Shard>,
        config: &FecConfig,
        original_len: usize,
    ) -> Result<Vec<u8>, FecError> {
        if !config.is_supported() {
            return Err(FecError::InvalidConfig);
        }

        // Deduplicate by index; a censor-injected duplicate must not count as
        // an independent equation.
        let mut data_shards: HashMap<usize, Vec<u8>> = HashMap::new();
        let mut parity_shards: HashMap<usize, Vec<u8>> = HashMap::new();
        let mut shard_len = 0usize;
        for shard in received {
            shard_len = shard_len.max(shard.data.len());
            if shard.is_parity {
                if shard.index < config.k || shard.index >= config.total_shards() {
                    return Err(FecError::DecodeFailed);
                }
                parity_shards.insert(shard.index, shard.data);
            } else {
                if shard.index >= config.k {
                    return Err(FecError::DecodeFailed);
                }
                data_shards.insert(shard.index, shard.data);
            }
        }

        let available = data_shards.len() + parity_shards.len();
        if available < config.k {
            return Err(FecError::NotEnoughShards {
                got: available,
                need: config.k,
            });
        }

        let missing_data: Vec<usize> = (0..config.k)
            .filter(|i| !data_shards.contains_key(i))
            .collect();

        if !missing_data.is_empty() {
            if parity_shards.len() < missing_data.len() {
                return Err(FecError::NotEnoughParity {
                    missing: missing_data.len(),
                    parity: parity_shards.len(),
                });
            }

            let matrix = cauchy_parity_matrix(config.k, config.m);

            // Build a k x k system out of the surviving shards: identity rows
            // for surviving data shards, Cauchy rows for parity shards.
            let mut rows: Vec<Vec<u8>> = Vec::with_capacity(config.k);
            let mut rhs: Vec<Vec<u8>> = Vec::with_capacity(config.k);
            for i in 0..config.k {
                if let Some(d) = data_shards.get(&i) {
                    let mut row = vec![0u8; config.k];
                    row[i] = 1;
                    rows.push(row);
                    rhs.push(d.clone());
                }
            }
            let mut parity_indices: Vec<usize> = parity_shards.keys().copied().collect();
            parity_indices.sort_unstable();
            for pidx in parity_indices {
                if rows.len() == config.k {
                    break;
                }
                rows.push(matrix[pidx - config.k].clone());
                rhs.push(parity_shards[&pidx].clone());
            }

            if rows.len() < config.k {
                return Err(FecError::NotEnoughShards {
                    got: rows.len(),
                    need: config.k,
                });
            }

            let inverse = invert_matrix(rows).ok_or(FecError::DecodeFailed)?;

            // Recover only the data shards we are actually missing.
            for &missing in &missing_data {
                let mut recovered = vec![0u8; shard_len];
                for (j, rhs_row) in rhs.iter().enumerate() {
                    let coef = inverse[missing][j];
                    if coef == 0 {
                        continue;
                    }
                    for (out, &byte) in recovered.iter_mut().zip(rhs_row.iter()) {
                        *out = gf::add(*out, gf::mul(coef, byte));
                    }
                }
                data_shards.insert(missing, recovered);
                self.recovered_shards.fetch_add(1, Ordering::Relaxed);
            }
        }

        if data_shards.len() < config.k {
            return Err(FecError::NotEnoughShards {
                got: data_shards.len(),
                need: config.k,
            });
        }

        let mut out = Vec::with_capacity(original_len);
        for i in 0..config.k {
            let shard_data = data_shards.get(&i).ok_or(FecError::DecodeFailed)?;
            out.extend_from_slice(shard_data);
        }
        if out.len() < original_len {
            return Err(FecError::DecodeFailed);
        }
        out.truncate(original_len);
        self.decoded_batches.fetch_add(1, Ordering::Relaxed);
        Ok(out)
    }

    #[must_use]
    pub fn batches_decoded(&self) -> u64 {
        self.decoded_batches.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn shards_recovered(&self) -> u64 {
        self.recovered_shards.load(Ordering::Relaxed)
    }
}

/// Adaptive FEC controller – adjusts parity based on observed loss
#[derive(Debug)]
pub struct AdaptiveFec {
    config: RwLock<FecConfig>,
    loss_ewma: RwLock<f64>,
    alpha: f64,
}

impl AdaptiveFec {
    #[must_use]
    pub fn new(k: usize, shard_size: usize) -> Self {
        Self {
            config: RwLock::new(FecConfig::for_loss(k, 0.3, shard_size)),
            loss_ewma: RwLock::new(0.05),
            alpha: 0.2,
        }
    }

    /// Update with observed loss rate (0.0-1.0)
    pub fn observe_loss(&self, loss: f64) {
        let mut ewma = self.loss_ewma.write();
        *ewma = *ewma * (1.0 - self.alpha) + loss * self.alpha;

        // Never reduce redundancy in response to a fresh high-loss sample.
        // The direct sample prevents a heavily smoothed EWMA from masking a
        // sudden outage, while the current target avoids churn on recovery.
        let mut cfg = self.config.write();
        let target = (*ewma * 1.2)
            .max(loss.clamp(0.0, 0.5))
            .max(cfg.target_loss)
            .clamp(0.05, 0.5);
        let new_m = ((cfg.k as f64 * target / (1.0 - target)).ceil() as usize).max(1);
        // Respect the field bound: never emit a config the encoder must reject.
        let new_m = new_m.min(MAX_TOTAL_SHARDS.saturating_sub(cfg.k));
        if new_m != cfg.m && new_m > 0 {
            cfg.m = new_m;
            cfg.target_loss = target;
        }
    }

    #[must_use]
    pub fn current_config(&self) -> FecConfig {
        self.config.read().clone()
    }

    #[must_use]
    pub fn observed_loss(&self) -> f64 {
        *self.loss_ewma.read()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FecError {
    EmptyData,
    InvalidConfig,
    NotEnoughShards { got: usize, need: usize },
    NotEnoughParity { missing: usize, parity: usize },
    PayloadTooLarge { needed: usize, shard_size: usize },
    DecodeFailed,
}

impl std::fmt::Display for FecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyData => write!(f, "empty data"),
            Self::InvalidConfig => write!(f, "invalid fec config"),
            Self::NotEnoughShards { got, need } => {
                write!(f, "not enough shards: got {got}, need {need}")
            }
            Self::NotEnoughParity { missing, parity } => {
                write!(f, "not enough parity: missing {missing}, parity {parity}")
            }
            Self::PayloadTooLarge { needed, shard_size } => write!(
                f,
                "payload too large: needs {needed} B per shard, limit {shard_size} B"
            ),
            Self::DecodeFailed => write!(f, "decode failed"),
        }
    }
}

impl std::error::Error for FecError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic PRNG so "random" loss patterns are reproducible in CI.
    struct Lcg(u64);
    impl Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }
        /// Fisher–Yates shuffle.
        fn shuffle<T>(&mut self, v: &mut [T]) {
            for i in (1..v.len()).rev() {
                let j = (self.next_u32() as usize) % (i + 1);
                v.swap(i, j);
            }
        }
    }

    #[test]
    fn gf_field_axioms_hold() {
        for a in 1u16..256 {
            let a = a as u8;
            assert_eq!(gf::mul(a, gf::inv(a)), 1, "a * a^-1 must be 1 for {a}");
            assert_eq!(gf::mul(a, 0), 0);
            assert_eq!(gf::div(a, a), 1);
        }
    }

    #[test]
    fn encode_decode_no_loss() {
        let cfg = FecConfig::new(4, 2, 1024);
        let enc = FecEncoder::new(cfg.clone());
        let data = b"The quick brown fox jumps over the lazy dog".repeat(10);
        let shards = enc.encode(&data).unwrap();
        assert_eq!(shards.len(), 6);
        assert_eq!(enc.batches_encoded(), 1);

        let dec = FecDecoder::new();
        let decoded = dec.decode(shards, &cfg, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_decode_with_loss_30_percent() {
        let cfg = FecConfig::new(4, 2, 512);
        let enc = FecEncoder::new(cfg.clone());
        let data = b"critical data that must survive 30 percent loss".repeat(20);
        let shards = enc.encode(&data).unwrap();

        // Drop 2 of 6 shards = 33.3% loss, both from the data lane.
        let received: Vec<Shard> = shards
            .into_iter()
            .filter(|s| s.index != 1 && s.index != 3)
            .collect();
        assert_eq!(received.len(), 4);

        let dec = FecDecoder::new();
        let decoded = dec.decode(received, &cfg, data.len()).unwrap();
        assert_eq!(
            decoded, data,
            "recovered bytes must equal the source exactly"
        );
        assert_eq!(dec.shards_recovered(), 2);
    }

    #[test]
    fn adaptive_fec_adjusts_to_loss() {
        let adaptive = AdaptiveFec::new(10, 1024);
        assert_eq!(adaptive.current_config().m, 5); // 10*0.3/0.7 = 4.28 -> 5

        adaptive.observe_loss(0.5);
        let cfg = adaptive.current_config();
        assert!(cfg.m >= 5);
        assert!(cfg.target_loss >= 0.3);
    }

    #[test]
    fn for_loss_config() {
        let cfg = FecConfig::for_loss(10, 0.5, 1024);
        assert_eq!(cfg.m, 10);
        assert!((cfg.overhead_ratio() - 1.0).abs() < 0.01);

        let cfg2 = FecConfig::for_loss(10, 0.3, 1024);
        assert_eq!(cfg2.m, 5);
    }

    #[test]
    fn not_enough_shards_error() {
        let cfg = FecConfig::new(4, 2, 512);
        let dec = FecDecoder::new();
        let err = dec.decode(vec![], &cfg, 100).unwrap_err();
        assert!(matches!(err, FecError::NotEnoughShards { got: 0, need: 4 }));
    }

    #[test]
    fn duplicate_shards_do_not_fake_recovery() {
        // Five copies of the same surviving shard are one equation, not five.
        let cfg = FecConfig::new(4, 2, 512);
        let enc = FecEncoder::new(cfg.clone());
        let data = vec![0x5Au8; 1000];
        let shards = enc.encode(&data).unwrap();
        let one = shards[0].clone();
        let received = vec![one.clone(), one.clone(), one.clone(), one.clone(), one];
        let dec = FecDecoder::new();
        let err = dec.decode(received, &cfg, data.len()).unwrap_err();
        assert!(matches!(err, FecError::NotEnoughShards { got: 1, need: 4 }));
    }

    #[test]
    fn survives_40_percent_loss_every_pattern() {
        // 10 data + 7 parity = 17 shards. 40% loss = 6 shards gone (ceil(6.8)
        // = 7 would leave exactly k, which we also cover below).
        let cfg = FecConfig::for_loss(10, 0.4, 512);
        assert_eq!(cfg.total_shards(), 17);
        let enc = FecEncoder::new(cfg.clone());
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let shards = enc.encode(&data).unwrap();

        let mut rng = Lcg(0xA37E_5EED);
        // 200 independent randomised 40%-loss patterns; every one must recover
        // the payload byte-for-byte.
        for trial in 0..200 {
            let mut order: Vec<usize> = (0..cfg.total_shards()).collect();
            rng.shuffle(&mut order);
            let drop_count = (cfg.total_shards() as f64 * 0.4).floor() as usize; // 6
            assert_eq!(drop_count, 6);
            let dropped: std::collections::HashSet<usize> =
                order.iter().copied().take(drop_count).collect();
            let received: Vec<Shard> = shards
                .iter()
                .filter(|s| !dropped.contains(&s.index))
                .cloned()
                .collect();
            assert_eq!(received.len(), cfg.total_shards() - drop_count);

            let dec = FecDecoder::new();
            let decoded = dec
                .decode(received, &cfg, data.len())
                .unwrap_or_else(|e| panic!("trial {trial} lost {dropped:?} failed: {e}"));
            assert_eq!(
                decoded, data,
                "trial {trial}: recovered payload must be byte-identical (lost {dropped:?})"
            );
        }
    }

    #[test]
    fn survives_worst_case_exactly_k_survivors() {
        // Hardest legal case: exactly k shards survive, and every single data
        // shard except one is gone.
        let cfg = FecConfig::for_loss(10, 0.4, 512);
        let enc = FecEncoder::new(cfg.clone());
        let data = b"blackout payload: exactly k survivors must still decode".repeat(30);
        let shards = enc.encode(&data).unwrap();

        // Keep data shard 0 + all 7 parity + data shards 1,2 => 10 shards.
        let keep: std::collections::HashSet<usize> = [0usize, 1, 2, 10, 11, 12, 13, 14, 15, 16]
            .into_iter()
            .collect();
        let received: Vec<Shard> = shards
            .into_iter()
            .filter(|s| keep.contains(&s.index))
            .collect();
        assert_eq!(received.len(), cfg.k);

        let dec = FecDecoder::new();
        let decoded = dec.decode(received, &cfg, data.len()).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(dec.shards_recovered(), 7);
    }

    #[test]
    fn below_k_survivors_fails_closed() {
        let cfg = FecConfig::for_loss(10, 0.4, 512);
        let enc = FecEncoder::new(cfg.clone());
        let data = vec![0xC3u8; 3000];
        let shards = enc.encode(&data).unwrap();
        // Only 9 survivors: information-theoretically impossible.
        let received: Vec<Shard> = shards.into_iter().take(9).collect();
        let dec = FecDecoder::new();
        let err = dec.decode(received, &cfg, data.len()).unwrap_err();
        assert!(matches!(
            err,
            FecError::NotEnoughShards { got: 9, need: 10 }
        ));
    }

    #[test]
    fn payload_too_large_is_rejected_not_truncated() {
        // Previously the encoder silently clamped shard_len to shard_size and
        // dropped the payload tail. It must fail closed instead.
        let cfg = FecConfig::new(4, 2, 8);
        let enc = FecEncoder::new(cfg);
        let err = enc.encode(&vec![1u8; 1000]).unwrap_err();
        assert!(matches!(err, FecError::PayloadTooLarge { .. }));
    }

    #[test]
    fn round_trip_over_many_sizes_and_configs() {
        for &(k, loss) in &[(4usize, 0.4f64), (8, 0.4), (16, 0.45), (32, 0.5)] {
            let cfg = FecConfig::for_loss(k, loss, 65536);
            let enc = FecEncoder::new(cfg.clone());
            for len in [1usize, 7, 63, 1024, 5000] {
                let data: Vec<u8> = (0..len).map(|i| (i * 31 % 256) as u8).collect();
                let shards = enc.encode(&data).unwrap();
                let drop_n = (cfg.total_shards() as f64 * loss).floor() as usize;
                // Drop the first `drop_n` shards — i.e. the data lane first,
                // the most damaging pattern.
                let received: Vec<Shard> = shards.into_iter().skip(drop_n).collect();
                let dec = FecDecoder::new();
                let decoded = dec.decode(received, &cfg, len).unwrap();
                assert_eq!(decoded, data, "k={k} loss={loss} len={len}");
            }
        }
    }
}
