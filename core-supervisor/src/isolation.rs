//! Isolation model — the formal 5-level classifier (§1 of the blackout directive).
//!
//! Distinguishes "one probe failed" from "the entire country is cut off." Transitions
//! up are debounced (one step at a time); recovery down is instant (first success → Nominal).

use std::cmp::Ordering;

/// Network isolation level. Strictly ordered; moves one step at a time going UP.
/// Recovery going DOWN skips straight to Nominal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// Primary core reachable.
    Nominal,
    /// Single-path degradation; hot-swap in progress.
    Degraded,
    /// Last-resort tier carrying traffic.
    Escalated,
    /// Tier also failed, sustained across debounce + multiple egresses.
    ConfirmedIsolation,
    /// ConfirmedIsolation persisted + no out-of-band healthy. The hard bound.
    TotalIsolation,
}

impl IsolationLevel {
    /// Numeric severity (0=Nominal … 4=TotalIsolation).
    #[must_use]
    pub fn severity(self) -> u8 {
        match self {
            Self::Nominal => 0,
            Self::Degraded => 1,
            Self::Escalated => 2,
            Self::ConfirmedIsolation => 3,
            Self::TotalIsolation => 4,
        }
    }

    /// Whether the hard bound is reached.
    #[must_use]
    pub fn is_hard_bound(self) -> bool {
        matches!(self, Self::TotalIsolation)
    }
}

impl PartialOrd for IsolationLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IsolationLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        self.severity().cmp(&other.severity())
    }
}

/// The correlator that classifies isolation from probe telemetry. Consumes the
/// same signals as `decider::LocalDecider` (success/failure) — does not re-implement
/// signal collection. Debounced on the way up; instant on the way down.
pub struct IsolationCorrelator {
    level: IsolationLevel,
    consecutive_failures: u32,
    /// Failures needed to advance one level (for levels above Degraded).
    debounce_threshold: u32,
    /// Whether any out-of-band interface is healthy. If true,
    /// `ConfirmedIsolation → TotalIsolation` is blocked.
    out_of_band_healthy: bool,
    /// Set to true when a recovery transition occurs (caller checks + resets).
    recovery_triggered: bool,
}

impl IsolationCorrelator {
    /// Create with a debounce threshold (default 5).
    #[must_use]
    pub fn new(debounce_threshold: u32) -> Self {
        Self {
            level: IsolationLevel::Nominal,
            consecutive_failures: 0,
            debounce_threshold: debounce_threshold.max(1),
            out_of_band_healthy: false,
            recovery_triggered: false,
        }
    }

    /// Update the out-of-band health flag (probed externally).
    pub fn set_out_of_band_healthy(&mut self, healthy: bool) {
        self.out_of_band_healthy = healthy;
    }

    /// Record a failed probe. May advance the level by one step (debounced).
    pub fn observe_failure(&mut self) {
        self.consecutive_failures += 1;
        let threshold = match self.level {
            IsolationLevel::Nominal => 1, // first failure → Degraded immediately
            _ => self.debounce_threshold,
        };
        if self.consecutive_failures >= threshold {
            self.advance_one_level();
            self.consecutive_failures = 0;
        }
    }

    /// Record a successful probe. Instantly drops to Nominal (the achievable
    /// "zero-second automatic recovery" guarantee). Sets `recovery_triggered`.
    pub fn observe_success(&mut self) {
        if self.level > IsolationLevel::Nominal {
            self.recovery_triggered = true;
        }
        self.level = IsolationLevel::Nominal;
        self.consecutive_failures = 0;
    }

    /// Whether a recovery transition occurred since the last check (caller calls
    /// `flush()` when this returns true, then it auto-resets).
    #[must_use]
    pub fn take_recovery_triggered(&mut self) -> bool {
        let r = self.recovery_triggered;
        self.recovery_triggered = false;
        r
    }

    /// Current isolation level.
    #[must_use]
    pub fn level(&self) -> IsolationLevel {
        self.level
    }

    /// Advance exactly one level. Blocked at TotalIsolation → TotalIsolation.
    /// ConfirmedIsolation → TotalIsolation is blocked while out-of-band is healthy.
    fn advance_one_level(&mut self) {
        self.level = match self.level {
            IsolationLevel::Nominal => IsolationLevel::Degraded,
            IsolationLevel::Degraded => IsolationLevel::Escalated,
            IsolationLevel::Escalated => IsolationLevel::ConfirmedIsolation,
            IsolationLevel::ConfirmedIsolation => {
                if self.out_of_band_healthy {
                    IsolationLevel::ConfirmedIsolation // blocked: OOB still up
                } else {
                    IsolationLevel::TotalIsolation
                }
            }
            IsolationLevel::TotalIsolation => IsolationLevel::TotalIsolation,
        };
    }
}

impl Default for IsolationCorrelator {
    fn default() -> Self {
        Self::new(5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_failure_reaches_degraded_but_no_further() {
        let mut c = IsolationCorrelator::new(5);
        c.observe_failure();
        assert_eq!(c.level(), IsolationLevel::Degraded);
        // A second single failure (without debounce threshold) stays at Degraded.
        c.observe_failure();
        assert_eq!(
            c.level(),
            IsolationLevel::Degraded,
            "must not advance past Degraded on <threshold failures"
        );
    }

    #[test]
    fn debounced_advancement_one_step_at_a_time() {
        let mut c = IsolationCorrelator::new(3);
        // Nominal → Degraded (1 failure).
        c.observe_failure();
        assert_eq!(c.level(), IsolationLevel::Degraded);
        // 3 failures → Escalated.
        for _ in 0..3 {
            c.observe_failure();
        }
        assert_eq!(c.level(), IsolationLevel::Escalated);
        // 3 more → ConfirmedIsolation.
        for _ in 0..3 {
            c.observe_failure();
        }
        assert_eq!(c.level(), IsolationLevel::ConfirmedIsolation);
        // 3 more → TotalIsolation (no OOB healthy).
        for _ in 0..3 {
            c.observe_failure();
        }
        assert_eq!(c.level(), IsolationLevel::TotalIsolation);
    }

    #[test]
    fn total_isolation_blocked_while_oob_healthy() {
        let mut c = IsolationCorrelator::new(2);
        c.set_out_of_band_healthy(true);
        // Climb to ConfirmedIsolation.
        for _ in 0..7 {
            c.observe_failure();
        }
        assert_eq!(c.level(), IsolationLevel::ConfirmedIsolation);
        // Try to advance — blocked.
        for _ in 0..4 {
            c.observe_failure();
        }
        assert_eq!(
            c.level(),
            IsolationLevel::ConfirmedIsolation,
            "blocked while OOB healthy"
        );
        // OOB goes down → now can advance.
        c.set_out_of_band_healthy(false);
        for _ in 0..2 {
            c.observe_failure();
        }
        assert_eq!(c.level(), IsolationLevel::TotalIsolation);
    }

    #[test]
    fn instant_recovery_from_any_level() {
        for start in [
            IsolationLevel::Degraded,
            IsolationLevel::Escalated,
            IsolationLevel::ConfirmedIsolation,
            IsolationLevel::TotalIsolation,
        ] {
            let mut c = IsolationCorrelator::new(1);
            // Climb to `start`.
            while c.level() < start {
                c.observe_failure();
            }
            assert_eq!(c.level(), start);
            // One success → instant Nominal.
            c.observe_success();
            assert_eq!(
                c.level(),
                IsolationLevel::Nominal,
                "instant recovery from {start:?}"
            );
            assert!(
                c.take_recovery_triggered(),
                "recovery flag set from {start:?}"
            );
        }
    }

    #[test]
    fn recovery_flag_not_set_when_already_nominal() {
        let mut c = IsolationCorrelator::new(5);
        c.observe_success(); // already Nominal
        assert!(!c.take_recovery_triggered());
    }

    #[test]
    fn severity_ordering() {
        assert!(IsolationLevel::Nominal < IsolationLevel::Degraded);
        assert!(IsolationLevel::Degraded < IsolationLevel::Escalated);
        assert!(IsolationLevel::Escalated < IsolationLevel::ConfirmedIsolation);
        assert!(IsolationLevel::ConfirmedIsolation < IsolationLevel::TotalIsolation);
        assert!(IsolationLevel::TotalIsolation.is_hard_bound());
    }

    #[test]
    fn no_oob_configured_trivially_allows_total() {
        // If no OOB is configured (healthy=false by default), TotalIsolation is reachable.
        let mut c = IsolationCorrelator::new(1);
        for _ in 0..10 {
            c.observe_failure();
        }
        assert_eq!(c.level(), IsolationLevel::TotalIsolation);
    }
}
