//! AI-DPI traffic-shaping model.
//!
//! This module computes packet-length targets, inter-arrival-time (IAT) jitter,
//! and candidate TLS-extension/cipher ordering for three hard-coded profiles.
//! It does **not** write padded bytes, sleep/delay a live flow, construct a TLS
//! ClientHello, or attach to Xray/sing-box. Consumers must prove those effects
//! in an authorized integration test before presenting this model as anti-DPI
//! traffic morphing.

use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

/// A domestic traffic profile the morpher can imitate.
#[derive(Debug, Clone)]
pub struct TrafficProfile {
    /// Profile name (e.g. "aparat-vod", "shaparak-banking").
    pub name: String,
    /// Target packet lengths to pad to (bytes).
    pub target_lengths: Vec<u32>,
    /// IAT jitter range in milliseconds [min, max].
    pub iat_jitter_ms: (u32, u32),
    /// TLS extension type order for JA4 fingerprint.
    pub ja4_extensions: Vec<u16>,
    /// Cipher suite list for the TLS ClientHello.
    pub cipher_suites: Vec<u16>,
    /// GREASE values to inject (RFC 8701).
    pub grease_values: Vec<u16>,
}

impl TrafficProfile {
    /// Aparat video streaming profile: large ~1400-byte chunks, smooth IAT.
    #[must_use]
    pub fn aparat_vod() -> Self {
        Self {
            name: "aparat-vod".into(),
            target_lengths: vec![1316, 1380, 1400, 1420],
            iat_jitter_ms: (8, 22),
            ja4_extensions: vec![0, 11, 10, 16, 43, 51, 13],
            cipher_suites: vec![4865, 4866, 4867, 49195, 49199],
            grease_values: vec![2570, 6682, 15730, 56032],
        }
    }

    /// SHAPARAK banking TLS profile: smaller, burstier packets.
    #[must_use]
    pub fn shaparak_banking() -> Self {
        Self {
            name: "shaparak-banking".into(),
            target_lengths: vec![512, 640, 768, 896],
            iat_jitter_ms: (30, 120),
            ja4_extensions: vec![0, 23, 65281, 10, 11, 16, 5],
            cipher_suites: vec![49195, 49196, 49199, 49200, 52393],
            grease_values: vec![1027, 9474, 47802, 36612],
        }
    }

    /// Generic HTTPS browsing profile.
    #[must_use]
    pub fn https_browsing() -> Self {
        Self {
            name: "https-browsing".into(),
            target_lengths: vec![517, 1200, 1400],
            iat_jitter_ms: (15, 80),
            ja4_extensions: vec![0, 11, 10, 16, 43, 51],
            cipher_suites: vec![4865, 4867, 4866, 49195, 49199],
            grease_values: vec![2570, 6682, 15730],
        }
    }
}

/// The traffic-shaping model. Picks a profile and calculates candidate length,
/// timing, and TLS-fingerprint values; it does not morph live packets.
/// Thread-safe; the active profile can be swapped at runtime.
pub struct TrafficMorpher {
    profiles: Vec<TrafficProfile>,
    active: RwLock<usize>,
    rotations: AtomicU64,
}

impl TrafficMorpher {
    /// Create a morpher with the three default Iranian-domestic profiles.
    #[must_use]
    pub fn with_default_profiles() -> Self {
        Self {
            profiles: vec![
                TrafficProfile::aparat_vod(),
                TrafficProfile::shaparak_banking(),
                TrafficProfile::https_browsing(),
            ],
            active: RwLock::new(0),
            rotations: AtomicU64::new(0),
        }
    }

    /// Get the active profile name.
    #[must_use]
    pub fn active_profile(&self) -> String {
        let idx = *self.active.read();
        if idx < self.profiles.len() {
            self.profiles[idx].name.clone()
        } else {
            "unknown".into()
        }
    }

    /// Select a profile by name (scenario-driven morphing, e.g. the blackout
    /// controller switching to the most-whitelisted domestic profile as
    /// isolation deepens). Returns true if a matching profile was found and
    /// activated. Thread-safe.
    pub fn select_profile(&self, name: &str) -> bool {
        for (i, p) in self.profiles.iter().enumerate() {
            if p.name == name {
                *self.active.write() = i;
                return true;
            }
        }
        false
    }

    /// Rotate to the next profile (circular). Returns the new profile name.
    pub fn rotate_profile(&self) -> String {
        let mut idx = self.active.write();
        *idx = (*idx + 1) % self.profiles.len();
        self.rotations.fetch_add(1, Ordering::Relaxed);
        self.profiles[*idx].name.clone()
    }

    /// Pad a packet to the nearest target length in the active profile.
    /// Returns the padded length (>= original).
    #[must_use]
    pub fn pad_packet(&self, original_len: u32) -> u32 {
        let idx = *self.active.read();
        if idx >= self.profiles.len() {
            return original_len;
        }
        let targets = &self.profiles[idx].target_lengths;
        // Find the smallest target >= original; if none, use the largest.
        for &t in targets {
            if t >= original_len {
                return t;
            }
        }
        targets.last().copied().unwrap_or(original_len)
    }

    /// Compute an IAT jitter (ms) for the active profile using a seed.
    #[must_use]
    pub fn iat_jitter_ms(&self, connection_seed: u64) -> u32 {
        let idx = *self.active.read();
        if idx >= self.profiles.len() {
            return 0;
        }
        let (min, max) = self.profiles[idx].iat_jitter_ms;
        if max <= min {
            return min;
        }
        let range = u64::from(max - min);
        let s = connection_seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        min + (s % range) as u32
    }

    /// Generate a randomized JA4 extension order for the active profile by
    /// shuffling extensions and injecting a random GREASE value.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
    pub fn ja4_fingerprint(&self, connection_seed: u64) -> JafFingerprint {
        let idx = *self.active.read();
        if idx >= self.profiles.len() {
            return JafFingerprint::default();
        }
        let profile = &self.profiles[idx];
        // Deterministic shuffle based on seed.
        let mut exts = profile.ja4_extensions.clone();
        let mut state = connection_seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        // Fisher-Yates with LCG.
        let n = exts.len();
        for i in (1..n).rev() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let j = (state % (u64::try_from(i).unwrap_or(u64::MAX) + 1)) as usize;
            exts.swap(i, j);
        }
        // Inject one GREASE value at a random position.
        let grease =
            profile.grease_values[(state % u64::from(profile.grease_values.len() as u32)) as usize];
        let insert_pos = (state % (u64::try_from(n).unwrap_or(0) + 1)) as usize;
        exts.insert(insert_pos.min(exts.len()), grease);

        JafFingerprint {
            extensions_order: exts,
            cipher_suites: profile.cipher_suites.clone(),
        }
    }

    /// Total profile rotations (for metrics).
    #[must_use]
    pub fn rotation_count(&self) -> u64 {
        self.rotations.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for TrafficMorpher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficMorpher")
            .field("profiles", &self.profiles.len())
            .field("active", &self.active_profile())
            .field("rotations", &self.rotation_count())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------
// Gaussian microsecond IAT perturbation (ML-DPI classifier evasion)
// ---------------------------------------------------------------------

/// A deterministic, allocation-free LCG mapping a u64 seed to a float in
/// the half-open interval (0, 1). Used by the Box-Muller transform below so
/// the Gaussian IAT jitter needs no `rand` dependency.
fn lcg_unit(seed: u64) -> f64 {
    // xorshift64* style mixing → normalise to (0,1).
    let mut x = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    let r = (x.wrapping_mul(0x2545_F491_4F6C_DD1D)) >> 11; // 53 high bits
                                                           // r in [0, 2^53); map to (0,1] avoiding exactly 0 (ln() blow-up).
    let unit = (r as f64) / (9_007_199_254_740_992.0_f64);
    if unit <= 0.0 {
        f64::MIN_POSITIVE
    } else {
        unit
    }
}

/// Gaussian (normal) inter-arrival-time perturbation in **microseconds**.
///
/// Complements [`TrafficMorpher::iat_jitter_ms`] (which is uniform): ML-based
/// DPI classifiers fit the *shape* of the IAT distribution, and real domestic
/// traffic (Aparat VOD, SHAPARAK banking) has a Gaussian, not uniform, IAT
/// profile. This returns a deterministic sample ~ N(mean_us, std_us²) from
/// `seed` via the Box-Muller transform — same seed ⇒ same sample, so it is
/// reproducible in tests and across a single connection.
///
/// Clamp to ±4σ guards against the long Box-Muller tail producing a pathological
/// delay.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]
pub fn gaussian_iat_jitter_us(seed: u64, mean_us: i64, std_us: f64) -> i64 {
    let std_us = std_us.max(0.0);
    let u1 = lcg_unit(seed);
    let u2 = lcg_unit(seed.wrapping_mul(2).wrapping_add(1));
    let r = (-2.0 * u1.ln()).sqrt();
    let theta = 2.0 * std::f64::consts::PI * u2;
    let mut z = r * theta.cos(); // standard normal
                                 // Clamp to ±4σ to bound the tail.
    z = z.clamp(-4.0, 4.0);
    mean_us + (z * std_us).round() as i64
}

/// A generated JA4 TLS fingerprint for one handshake.
#[derive(Debug, Clone, Default)]
pub struct JafFingerprint {
    pub extensions_order: Vec<u16>,
    pub cipher_suites: Vec<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_rounds_up_to_target() {
        let m = TrafficMorpher::with_default_profiles();
        // Aparat profile (active by default): targets [1316, 1380, 1400, 1420].
        assert_eq!(m.pad_packet(500), 1316);
        assert_eq!(m.pad_packet(1350), 1380);
        assert_eq!(m.pad_packet(5000), 1420); // above all -> largest
    }

    #[test]
    fn iat_jitter_in_range() {
        let m = TrafficMorpher::with_default_profiles();
        for seed in 0..1000 {
            let jitter = m.iat_jitter_ms(seed);
            assert!((8..=22).contains(&jitter), "jitter {jitter} out of [8,22]");
        }
    }

    #[test]
    fn rotate_changes_profile() {
        let m = TrafficMorpher::with_default_profiles();
        assert_eq!(m.active_profile(), "aparat-vod");
        assert_eq!(m.rotate_profile(), "shaparak-banking");
        assert_eq!(m.rotate_profile(), "https-browsing");
        assert_eq!(m.rotate_profile(), "aparat-vod"); // wraps
        assert_eq!(m.rotation_count(), 3);
    }

    #[test]
    fn ja4_is_unique_across_seeds() {
        let m = TrafficMorpher::with_default_profiles();
        let f1 = m.ja4_fingerprint(1);
        let f2 = m.ja4_fingerprint(999);
        assert!(!f1.extensions_order.is_empty());
        assert!(!f2.extensions_order.is_empty());
        // Very likely different orderings.
        assert_ne!(f1.extensions_order, f2.extensions_order);
    }

    #[test]
    fn ja4_includes_grease() {
        let m = TrafficMorpher::with_default_profiles();
        let fp = m.ja4_fingerprint(42);
        let grease_set: std::collections::HashSet<_> = TrafficProfile::aparat_vod()
            .grease_values
            .iter()
            .copied()
            .collect();
        assert!(
            fp.extensions_order.iter().any(|e| grease_set.contains(e)),
            "no GREASE value in JA4 extensions"
        );
    }

    #[test]
    fn gaussian_iat_is_bounded_and_centered() {
        // Over many seeds, samples stay within ±4σ of the mean and cluster near it.
        let mean = 500_i64;
        let std_dev = 80.0_f64;
        let mut sum = 0_i64;
        let mut max_abs = 0_i64;
        for seed in 0..2000u64 {
            let j = gaussian_iat_jitter_us(seed, mean, std_dev);
            sum += j - mean;
            max_abs = max_abs.max((j - mean).abs());
        }
        let avg = sum as f64 / 2000.0;
        // Mean of the perturbation should be near zero (Gaussian centered).
        assert!(avg.abs() < 15.0, "gaussian IAT mean drifted: {avg}");
        // No sample exceeds ±4σ = ±320us.
        assert!(max_abs <= 320, "gaussian IAT exceeded 4σ: {max_abs}");
    }

    #[test]
    fn gaussian_iat_is_deterministic_per_seed_and_bounded() {
        let a = gaussian_iat_jitter_us(42, 1000, 50.0);
        // Same seed ⇒ identical sample (reproducible across a connection).
        assert_eq!(a, gaussian_iat_jitter_us(42, 1000, 50.0));
        // Every sample stays within mean ± 4σ regardless of seed.
        for seed in 0..500u64 {
            let j = gaussian_iat_jitter_us(seed, 1000, 50.0);
            assert!((800..=1200).contains(&j), "out of 4σ band: {j}");
        }
    }
}
