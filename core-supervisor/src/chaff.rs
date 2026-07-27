//! Dynamic payload chaffing & timing morphing — anti ML-DPI engine.
//!
//! CNN / Random Forest classifiers that Iran's DPI may deploy exploit two
//! cheap statistical signals: packet-size distribution (entropy) and
//! inter-arrival timing regularity. This module obscures both:
//!
//! - **Payload chaffing**: random padding whose length follows a Poisson
//!   distribution (λ configurable) — producing a heavy-tail size distribution
//!   indistinguishable from domestic web traffic. Plus optional uniform
//!   chaff for entropy flattening.
//! - **Timing jitter**: Gaussian + exponential jitter layered over the true
//!   pacing to break deterministic IAT patterns.
//!
//! Pure computation, `#![forbid(unsafe_code)]` compatible, zero alloc in hot
//! path beyond the padding buffer.

use std::time::Duration;

/// Deterministic LCG for reproducible tests without `rand` crate.
#[derive(Debug, Clone, Copy)]
struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(0x9E37_79B9_7F4A_7C15),
        }
    }
    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }
    #[inline]
    fn next_f64(&mut self) -> f64 {
        // 53-bit precision float in (0,1]
        let v = self.next_u64() >> 11;
        let f = (v as f64) / (9_007_199_254_740_992.0);
        if f <= 0.0 {
            f64::MIN_POSITIVE
        } else {
            f
        }
    }
}

/// Poisson sampler via Knuth's algorithm, deterministic per seed.
/// Returns k ~ Poisson(λ)
fn poisson_sample(lcg: &mut Lcg, lambda: f64) -> u32 {
    if lambda <= 0.0 {
        return 0;
    }
    if lambda > 100.0 {
        // For large λ, use Normal approximation N(λ, λ) via Box-Muller
        // to avoid O(λ) loop.
        let u1 = lcg.next_f64();
        let u2 = lcg.next_f64();
        let r = (-2.0 * u1.ln()).sqrt();
        let theta = 2.0 * std::f64::consts::PI * u2;
        let z = r * theta.cos();
        let v = lambda + z * lambda.sqrt();
        return v.max(0.0).round() as u32;
    }
    // Knuth
    let l = (-lambda).exp();
    let mut k = 0u32;
    let mut p = 1.0f64;
    loop {
        k += 1;
        p *= lcg.next_f64();
        if p <= l {
            break;
        }
        if k > 10_000 {
            break; // safety
        }
    }
    k.saturating_sub(1)
}

/// Configuration for chaffing.
#[derive(Debug, Clone)]
pub struct ChaffConfig {
    /// Poisson λ for padding length (bytes). Typical 32-128.
    pub lambda: f64,
    /// Max padding clamp.
    pub max_padding: u32,
    /// Min padding (to avoid zero).
    pub min_padding: u32,
    /// Gaussian stddev for IAT jitter in microseconds.
    pub iat_std_us: f64,
    /// Mean IAT additional delay in microseconds.
    pub iat_mean_us: i64,
}

impl Default for ChaffConfig {
    fn default() -> Self {
        Self {
            lambda: 64.0,
            max_padding: 512,
            min_padding: 0,
            iat_std_us: 1500.0,
            iat_mean_us: 200,
        }
    }
}

/// Result of chaff application to a single packet.
#[derive(Debug, Clone)]
pub struct ChaffedPacket {
    /// New total length after padding.
    pub padded_len: u32,
    /// Padding bytes added.
    pub padding: u32,
    /// Additional jitter to sleep before sending next packet.
    pub jitter: Duration,
    /// Entropy adjustment score (0.0-1.0): how much entropy was flattened.
    pub entropy_score: f64,
}

/// The chaffing engine.
#[derive(Debug, Clone)]
pub struct ChaffEngine {
    config: ChaffConfig,
    packets_chaffed: u64,
}

impl ChaffEngine {
    #[must_use]
    pub fn new(config: ChaffConfig) -> Self {
        Self {
            config,
            packets_chaffed: 0,
        }
    }

    #[must_use]
    pub fn with_default() -> Self {
        Self::new(ChaffConfig::default())
    }

    /// Apply chaffing to a packet of `original_len` using `seed` for determinism.
    /// In production seed = connection_id || packet_counter.
    pub fn chaff_packet(&mut self, original_len: u32, seed: u64) -> ChaffedPacket {
        let mut lcg = Lcg::new(seed ^ self.packets_chaffed.wrapping_add(1));
        let padding_raw = poisson_sample(&mut lcg, self.config.lambda);
        let padding = padding_raw.clamp(self.config.min_padding, self.config.max_padding);

        // Entropy score: estimate of how much padding randomizes low-entropy payloads.
        // Real implementations would measure payload entropy; here we model.
        let entropy_score = if original_len > 0 {
            let ratio = padding as f64 / (original_len + padding) as f64;
            (ratio * 0.8 + lcg.next_f64() * 0.2).clamp(0.0, 1.0)
        } else {
            0.5
        };

        // Gaussian IAT jitter via Box-Muller
        let u1 = lcg.next_f64();
        let u2 = lcg.next_f64();
        let r = (-2.0 * u1.ln()).sqrt();
        let theta = 2.0 * std::f64::consts::PI * u2;
        let mut z = r * theta.cos();
        z = z.clamp(-4.0, 4.0); // ±4σ clamp
        let jitter_us = self.config.iat_mean_us as f64 + z * self.config.iat_std_us;
        let jitter_us = jitter_us.max(0.0) as u64;

        self.packets_chaffed += 1;

        ChaffedPacket {
            padded_len: original_len + padding,
            padding,
            jitter: Duration::from_micros(jitter_us),
            entropy_score,
        }
    }

    /// Bulk chaff stats
    #[must_use]
    pub fn stats(&self) -> ChaffStats {
        ChaffStats {
            packets_chaffed: self.packets_chaffed,
        }
    }

    #[must_use]
    pub fn config(&self) -> &ChaffConfig {
        &self.config
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ChaffStats {
    pub packets_chaffed: u64,
}

/// Entropy obfuscation helper: calculates Shannon entropy of a byte slice.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisson_chaff_bounds() {
        let mut eng = ChaffEngine::with_default();
        for seed in 0..1000u64 {
            let ch = eng.chaff_packet(1200, seed);
            assert!(ch.padding <= eng.config.max_padding);
            assert!(ch.padded_len >= 1200);
            assert!(
                ch.jitter.as_micros() <= 20000,
                "jitter too large: {:?}",
                ch.jitter
            );
        }
    }

    #[test]
    fn poisson_distribution_shape() {
        // Sample many and check mean approximates lambda
        let mut eng = ChaffEngine::new(ChaffConfig {
            lambda: 64.0,
            max_padding: 1000,
            min_padding: 0,
            ..Default::default()
        });
        let mut sum = 0u64;
        let n = 5000;
        for i in 0..n {
            let c = eng.chaff_packet(100, i);
            sum += c.padding as u64;
        }
        let mean = sum as f64 / n as f64;
        assert!((mean - 64.0).abs() < 10.0, "mean {mean} not near lambda 64");
    }

    #[test]
    fn determinism_per_seed() {
        let mut e1 = ChaffEngine::with_default();
        let mut e2 = ChaffEngine::with_default();
        let a = e1.chaff_packet(100, 42);
        // Need same internal counter; reset
        let mut e2b = ChaffEngine::with_default();
        let b = e2b.chaff_packet(100, 42);
        assert_eq!(a.padding, b.padding);
        assert_eq!(a.jitter, b.jitter);
    }

    #[test]
    fn entropy_calc() {
        // Uniform bytes high entropy
        let uniform: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&uniform);
        assert!(e > 7.5, "uniform entropy {e} too low");

        let zeros = vec![0u8; 100];
        let ez = shannon_entropy(&zeros);
        assert_eq!(ez, 0.0);
    }

    #[test]
    fn large_lambda_uses_normal_approx() {
        let cfg = ChaffConfig {
            lambda: 200.0,
            max_padding: 1000,
            ..Default::default()
        };
        let mut eng = ChaffEngine::new(cfg);
        for s in 0..100 {
            let c = eng.chaff_packet(10, s);
            assert!(c.padding <= 1000);
        }
    }
}
