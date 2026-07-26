//! Local adaptive decider.
//!
//! This turns a stream of probe outcomes (success / failure-with-cause) into a
//! [`policy::Decision`] by feeding a windowed [`telemetry::RollingSuccess`]
//! signature into the existing [`policy::FallbackEngine`].
//!
//! It is deliberately non-duplicative: it owns *no* decision logic of its own.
//! Every rule (when to keep, switch, or escalate) lives in
//! [`policy::FallbackEngine`]; this module only aggregates observations into a
//! [`policy::FailureSignature`] and asks the engine. That keeps the fallback
//! policy as a single source of truth shared with the AI path.

use crate::policy::{Decision, FailureSignature, FallbackEngine};
use crate::telemetry::RollingSuccess;

/// Categorical cause of a failed probe. Maps onto the signal rates the engine
/// reasons about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailKind {
    /// TCP RST injected mid-stream (active DPI).
    RstInjection,
    /// TLS handshake truncated (alert / early close during ClientHello).
    TlsTruncation,
    /// DNS resolution diverged from a known-good anchor.
    DnsAnomaly,
    /// Generic failure with no specific signature.
    Generic,
}

/// A per-instance adaptive decider. Windowed; bounded memory.
pub struct LocalDecider {
    engine: FallbackEngine,
    current: String,
    window: usize,
    // One windowed ring per signal; success_rate of each ring = that signal's rate.
    success: RollingSuccess,
    rst: RollingSuccess,
    trunc: RollingSuccess,
    dns: RollingSuccess,
}

impl LocalDecider {
    /// Construct a decider for `current_protocol` with `window` samples and a
    /// given (possibly customized) [`FallbackEngine`].
    pub fn new(current_protocol: impl Into<String>, window: usize, engine: FallbackEngine) -> Self {
        Self {
            engine,
            current: current_protocol.into(),
            window,
            success: RollingSuccess::new(window),
            rst: RollingSuccess::new(window),
            trunc: RollingSuccess::new(window),
            dns: RollingSuccess::new(window),
        }
    }

    /// Record a successful probe.
    pub fn observe_success(&mut self) {
        self.success.record(true);
        self.rst.record(false);
        self.trunc.record(false);
        self.dns.record(false);
    }

    /// Record a failed probe categorized by `kind`.
    pub fn observe_failure(&mut self, kind: FailKind) {
        self.success.record(false);
        self.rst.record(matches!(kind, FailKind::RstInjection));
        self.trunc.record(matches!(kind, FailKind::TlsTruncation));
        self.dns.record(matches!(kind, FailKind::DnsAnomaly));
    }

    /// Snapshot the current windowed signature.
    pub fn signature(&self) -> FailureSignature {
        let (sample_count, success_rate) = self.success.stats();
        FailureSignature {
            sample_count,
            success_rate,
            tcp_rst_rate: self.rst.stats().1,
            tls_trunc_rate: self.trunc.stats().1,
            dns_anomaly_rate: self.dns.stats().1,
        }
    }

    /// Ask the engine for the current recommendation.
    pub fn decide(&self) -> Decision {
        self.engine.decide(&self.current, self.signature())
    }

    /// The protocol currently in effect.
    pub fn current_protocol(&self) -> &str {
        &self.current
    }

    /// Advance the decider to a new protocol (e.g. after a successful switch)
    /// and reset the observation windows so stale signals do not carry over.
    pub fn advance_to(&mut self, protocol: impl Into<String>) {
        self.current = protocol.into();
        self.success = RollingSuccess::new(self.window);
        self.rst = RollingSuccess::new(self.window);
        self.trunc = RollingSuccess::new(self.window);
        self.dns = RollingSuccess::new(self.window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Decision;

    fn decider() -> LocalDecider {
        // Default engine: min_samples 20, switch_threshold 0.85.
        LocalDecider::new("reality-vision", 64, FallbackEngine::default())
    }

    #[test]
    fn healthy_stays() {
        let mut d = decider();
        for _ in 0..30 {
            d.observe_success();
        }
        assert_eq!(d.decide(), Decision::Keep("reality-vision".into()));
    }

    #[test]
    fn rst_storm_switches() {
        let mut d = decider();
        for _ in 0..30 {
            d.observe_failure(FailKind::RstInjection);
        }
        assert_eq!(d.decide(), Decision::Switch("hysteria2".into()));
    }

    #[test]
    fn dns_anomaly_escalates() {
        let mut d = decider();
        for _ in 0..30 {
            d.observe_failure(FailKind::DnsAnomaly);
        }
        assert_eq!(d.decide(), Decision::Escalate);
    }

    #[test]
    fn too_few_samples_keeps() {
        let mut d = decider();
        for _ in 0..5 {
            d.observe_failure(FailKind::RstInjection);
        }
        assert_eq!(d.decide(), Decision::Keep("reality-vision".into()));
    }

    #[test]
    fn advance_resets_and_redecides() {
        let mut d = decider();
        for _ in 0..30 {
            d.observe_failure(FailKind::RstInjection);
        }
        // Switch to hysteria2, then confirm a clean window keeps it.
        d.advance_to("hysteria2");
        assert_eq!(d.current_protocol(), "hysteria2");
        for _ in 0..30 {
            d.observe_success();
        }
        assert_eq!(d.decide(), Decision::Keep("hysteria2".into()));
    }
}
