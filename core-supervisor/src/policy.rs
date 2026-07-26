//! Deterministic fallback policy + the non-AI fallback engine.
//!
//! Per `ARCHITECTURE.md` §1.4, the system must "fail open to a heuristic, not
//! to silence." This module is that heuristic: a pure, testable state machine
//! that produces a fallback decision from a windowed failure signature, with
//! **zero** dependency on the ONNX inference engine. The AI layer, when
//! available, simply pushes a [`Policy`] with a learned `fallback_chain`; when
//! it is unavailable, [`FallbackEngine`] recomputes one.

use serde::{Deserialize, Serialize};

use crate::fragmentation::FragmentationPolicy;

/// A push-down policy for one instance. Revisioned and monotonic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub protocol_id: String,
    pub fragmentation: FragmentationPolicy,
    /// Ordered list of protocols to try. First wins.
    pub fallback_chain: Vec<String>,
    /// Monotonic revision; supervisor rejects stale revisions.
    pub revision: u64,
}

impl Policy {
    /// A neutral default used in tests and as the initial policy.
    pub fn default_for(protocol_id: &str) -> Self {
        Self {
            protocol_id: protocol_id.into(),
            fragmentation: FragmentationPolicy::default(),
            fallback_chain: vec![],
            revision: 0,
        }
    }
}

/// A windowed failure signature the engine reasons about. Populated from the
/// telemetry stream; deliberately coarse-grained for determinism.
#[derive(Debug, Clone, Copy, Default)]
pub struct FailureSignature {
    pub sample_count: u32,
    pub success_rate: f64, // [0,1]
    pub tcp_rst_rate: f64, // fraction of samples that saw an injected RST
    pub tls_trunc_rate: f64,
    pub dns_anomaly_rate: f64,
}

/// What the engine recommends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Current protocol is fine; keep it.
    Keep(String),
    /// Switch to this next protocol in the cascade.
    Switch(String),
    /// Nothing left in the chain; surface to the control plane for human/escalation.
    Escalate,
}

/// The canonical cascade. Matches `ARCHITECTURE.md` §3.4. Ordered most-likely
/// to survive first.
pub const DEFAULT_CASCADE: &[&str] = &[
    "reality-vision",
    "hysteria2",
    "tuic-v5",
    "shadowtls-v3-ss2022",
    "amneziawg",
    "persis-cover-front",
];

/// The DPI signal rate (max of TCP-RST / TLS-truncation) above which the
/// engine switches protocol. **Single source of truth** — the predictive
/// [`crate::dpi_forecast`] layer calibrates against this rather than
/// re-declaring its own copy, so the two can never drift apart.
pub const DPI_SWITCH_RATE: f64 = 0.3;

/// The DNS-anomaly rate above which the engine escalates instead of switching
/// (network-wide poisoning: another protocol will not help).
pub const DNS_ESCALATE_RATE: f64 = 0.5;

/// Default success rate below which the engine switches protocol.
pub const DEFAULT_SWITCH_THRESHOLD: f64 = 0.85;

/// Default number of windowed samples required before the engine acts at all.
/// This debounce is *why* a purely reactive path always lags a real block —
/// and therefore why [`crate::dpi_forecast`] exists.
pub const DEFAULT_MIN_SAMPLES: u32 = 20;

/// A pure, deterministic fallback decider.
pub struct FallbackEngine {
    cascade: Vec<String>,
    /// Number of samples required before acting (avoids flapping on noise).
    min_samples: u32,
    /// Success rate below which we move to the next protocol.
    switch_threshold: f64,
}

impl Default for FallbackEngine {
    fn default() -> Self {
        Self {
            cascade: DEFAULT_CASCADE.iter().map(|s| (*s).to_string()).collect(),
            min_samples: DEFAULT_MIN_SAMPLES,
            switch_threshold: DEFAULT_SWITCH_THRESHOLD,
        }
    }
}

impl FallbackEngine {
    /// Decide for `current` given the latest [`FailureSignature`].
    ///
    /// Rules (in order, first match wins — fully deterministic):
    ///   1. Not enough samples → Keep (avoid premature flapping).
    ///   2. DNS anomaly dominant → Escalate (likely network-wide poisoning;
    ///      switching protocol won't help).
    ///   3. TLS truncation / TCP-RST dominant OR success < threshold →
    ///      Switch to the next protocol in the cascade after `current`.
    ///   4. Otherwise → Keep.
    pub fn decide(&self, current: &str, sig: FailureSignature) -> Decision {
        if sig.sample_count < self.min_samples {
            return Decision::Keep(current.to_string());
        }

        let dpi_signal = sig.tcp_rst_rate.max(sig.tls_trunc_rate);
        if sig.dns_anomaly_rate > DNS_ESCALATE_RATE {
            return Decision::Escalate;
        }

        if dpi_signal > DPI_SWITCH_RATE || sig.success_rate < self.switch_threshold {
            return self.next_after(current);
        }

        Decision::Keep(current.to_string())
    }

    /// Next protocol in the cascade after `current`, or [`Decision::Escalate`].
    pub fn next_after(&self, current: &str) -> Decision {
        match self.cascade.iter().position(|p| p == current) {
            Some(i) if i + 1 < self.cascade.len() => Decision::Switch(self.cascade[i + 1].clone()),
            _ => Decision::Escalate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(n: u32, success: f64, rst: f64, trunc: f64, dns: f64) -> FailureSignature {
        FailureSignature {
            sample_count: n,
            success_rate: success,
            tcp_rst_rate: rst,
            tls_trunc_rate: trunc,
            dns_anomaly_rate: dns,
        }
    }

    #[test]
    fn keep_when_healthy() {
        let e = FallbackEngine::default();
        assert_eq!(
            e.decide("reality-vision", sig(100, 0.98, 0.0, 0.0, 0.0)),
            Decision::Keep("reality-vision".into())
        );
    }

    #[test]
    fn keep_when_too_few_samples() {
        let e = FallbackEngine::default();
        assert_eq!(
            e.decide("reality-vision", sig(5, 0.0, 0.9, 0.0, 0.0)),
            Decision::Keep("reality-vision".into())
        );
    }

    #[test]
    fn switch_on_rst_storm() {
        let e = FallbackEngine::default();
        assert_eq!(
            e.decide("reality-vision", sig(50, 0.2, 0.6, 0.0, 0.0)),
            Decision::Switch("hysteria2".into())
        );
    }

    #[test]
    fn escalate_on_dns_poisoning() {
        let e = FallbackEngine::default();
        assert_eq!(
            e.decide("reality-vision", sig(50, 0.1, 0.0, 0.0, 0.8)),
            Decision::Escalate
        );
    }

    #[test]
    fn escalate_past_last_protocol() {
        let e = FallbackEngine::default();
        assert_eq!(
            e.decide("persis-cover-front", sig(50, 0.1, 0.6, 0.0, 0.0)),
            Decision::Escalate
        );
    }

    #[test]
    fn cascade_next_after_is_positional() {
        let e = FallbackEngine::default();
        assert_eq!(
            e.next_after("tuic-v5"),
            Decision::Switch("shadowtls-v3-ss2022".into())
        );
        assert_eq!(e.next_after("not-in-cascade"), Decision::Escalate);
    }
}
