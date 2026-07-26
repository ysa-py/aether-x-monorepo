//! Probe cadence governor — **disciplined waiting instead of a retry storm**.
//!
//! `BLACKOUT_BOUNDS.md` §ConfirmedIsolation makes a specific operational
//! commitment: when the exit is gone, the system "stops generating
//! high-frequency retry traffic (battery and network-footprint discipline — a
//! retry storm during a blackout is both wasteful and a signal to the censor)"
//! and falls back to "one probe per transport every 30 s".
//!
//! That commitment was written down but never implemented — nothing in the
//! crate governed retry timing at all. This module is that governor.
//!
//! ## Why this is not cosmetic
//!
//! During a national blackout an ungoverned client retries as fast as its loop
//! allows, and three things follow:
//!
//! 1. **Battery burns** at the exact moment recharging may be unreliable. A
//!    dead phone is a disconnected user, no matter how good the transports are.
//! 2. **The censor gets a signal.** A device emitting a steady, high-rate
//!    stream of failing handshakes to known circumvention endpoints is *louder*
//!    than normal traffic and trivially classifiable. Backing off is not just
//!    polite, it is camouflage.
//! 3. **Synchronised retries self-collide.** Every device in a city reacting to
//!    the same cut at the same instant produces a thundering herd against the
//!    few surviving paths — the herd itself becomes the outage. Decorrelated
//!    jitter is the standard fix and is applied here.
//!
//! ## The one thing it must never do
//!
//! Back-off must never delay *recovery*. The whole point of the blackout design
//! is that the first successful probe returns the user to Nominal instantly. So
//! [`ProbeCadence::note_success`] resets the schedule to the aggressive floor
//! immediately, and [`ProbeCadence::force_due`] lets an external
//! wake-up (network-change event, user action, mesh peer reporting a live path)
//! bypass the delay entirely. Backing off is for *repeated failure*, never for
//! a path that just came back.
//!
//! ## Non-duplication
//!
//! No other module schedules anything. [`crate::isolation`] classifies *level*,
//! [`crate::dpi_forecast`] predicts *hazard*, [`crate::seamless`] decides *what
//! to connect to*. This decides **when to try again**, which nothing else owns.
//! It performs no I/O and drives no clock — the caller supplies `now`, so the
//! policy is fully deterministic and testable without sleeping.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::isolation::IsolationLevel;

/// Fastest retry interval, used while the network still looks usable.
pub const FLOOR_INTERVAL: Duration = Duration::from_millis(500);

/// Cadence at `ConfirmedIsolation`, matching the documented commitment of one
/// probe per transport every 30 s.
pub const CONFIRMED_ISOLATION_INTERVAL: Duration = Duration::from_secs(30);

/// Cadence at `TotalIsolation`. Slower still: at the hard bound there is
/// provably nothing to reach internationally, so probing is pure cost until
/// the physical situation changes.
pub const TOTAL_ISOLATION_INTERVAL: Duration = Duration::from_secs(60);

/// Absolute ceiling on any computed interval.
pub const MAX_INTERVAL: Duration = Duration::from_secs(300);

/// Exponential growth factor applied per consecutive failure.
const BACKOFF_FACTOR: u32 = 2;

/// Consecutive failures after which growth stops (the cap is reached quickly;
/// beyond this the level-based floor dominates anyway).
const MAX_BACKOFF_SHIFT: u32 = 8;

/// Fraction of the interval used as decorrelating jitter, in percent.
///
/// ±25 % is wide enough to break synchronisation across a city's worth of
/// devices without making any single device's cadence unpredictable to itself.
const JITTER_PERCENT: u64 = 25;

/// Map a [`crate::blackout::IsolationLevel`] onto the cadence model's
/// [`IsolationLevel`].
///
/// The crate carries two isolation enums on purpose, and they are not
/// duplicates of each other:
///
/// * [`crate::blackout::IsolationLevel`] is a **cause** model — *what the
///   censor has done* (DPI active, routing severed, DNS severed). It is
///   classified statelessly from one signal snapshot.
/// * [`crate::isolation::IsolationLevel`] is a **confidence** model — *how sure
///   we are, over time* (one probe failed vs. sustained multi-egress failure).
///   It is debounced on the way up and instant on the way down.
///
/// Retry cadence is a function of confidence, not of cause: a single failed
/// probe must not trigger blackout-grade back-off. This function is the one
/// place the two models meet, so the relationship is explicit and reviewable
/// rather than implied by matching names.
///
/// The mapping is deliberately conservative — it never reports *more*
/// confidence than the cause model justifies, so cadence can only ever be too
/// fast (costing battery), never too slow (costing recovery time).
#[must_use]
pub fn level_from_blackout(level: crate::blackout::IsolationLevel) -> IsolationLevel {
    use crate::blackout::IsolationLevel as B;
    match level {
        B::Normal => IsolationLevel::Nominal,
        B::DpiBlocking => IsolationLevel::Degraded,
        // Routing severed: the last-resort tier is carrying traffic.
        B::RoutingSevered => IsolationLevel::Escalated,
        // The hard bound. Deliberately mapped to ConfirmedIsolation rather than
        // TotalIsolation: TotalIsolation additionally requires that no
        // out-of-band uplink is healthy, which the cause model does not observe.
        // Under-reporting here keeps probing slightly more eager than strictly
        // necessary, which is the safe direction to be wrong in.
        B::FullIsolation => IsolationLevel::ConfirmedIsolation,
    }
}

/// The base cadence mandated for an isolation level, before back-off.
///
/// Pure and total: every level maps to exactly one interval, so this can never
/// panic or fall through.
#[must_use]
pub fn base_interval_for(level: IsolationLevel) -> Duration {
    match level {
        // A working or merely degraded path: stay responsive.
        IsolationLevel::Nominal | IsolationLevel::Degraded => FLOOR_INTERVAL,
        // Riding the last-resort tier: moderate, still trying to improve.
        IsolationLevel::Escalated => Duration::from_secs(5),
        // The documented discipline points.
        IsolationLevel::ConfirmedIsolation => CONFIRMED_ISOLATION_INTERVAL,
        IsolationLevel::TotalIsolation => TOTAL_ISOLATION_INTERVAL,
    }
}

/// Per-transport scheduling state.
#[derive(Debug, Clone)]
struct TransportState {
    /// Consecutive failures since the last success.
    consecutive_failures: u32,
    /// When this transport may next be probed.
    next_due: Instant,
    /// Total probes permitted for this transport.
    probes_allowed: u64,
    /// Total probes suppressed by the governor for this transport.
    probes_suppressed: u64,
}

impl TransportState {
    fn new(now: Instant) -> Self {
        Self {
            consecutive_failures: 0,
            // Immediately probeable on first sight.
            next_due: now,
            probes_allowed: 0,
            probes_suppressed: 0,
        }
    }
}

/// Aggregate cadence metrics — the evidence that discipline is real.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CadenceStats {
    /// Probes the governor permitted.
    pub allowed: u64,
    /// Probes the governor suppressed (the battery/footprint saving).
    pub suppressed: u64,
    /// Times a success reset a transport to the floor cadence.
    pub resets: u64,
    /// Times an external wake-up bypassed the schedule.
    pub forced: u64,
}

impl CadenceStats {
    /// Fraction of probe attempts that were suppressed, in `[0, 1]`.
    #[must_use]
    pub fn suppression_ratio(&self) -> f64 {
        let total = self.allowed + self.suppressed;
        if total == 0 {
            return 0.0;
        }
        self.suppressed as f64 / total as f64
    }
}

/// The probe cadence governor.
///
/// Thread-safe and clock-injected: every method takes `now`, so the entire
/// policy is deterministic and unit-testable without sleeping.
pub struct ProbeCadence {
    level: RwLock<IsolationLevel>,
    transports: RwLock<HashMap<String, TransportState>>,
    stats: RwLock<CadenceStats>,
    /// Deterministic decorrelation source. Seeded per instance; mixed with the
    /// transport name so two transports never share a schedule.
    jitter_seed: RwLock<u64>,
}

impl ProbeCadence {
    /// Create a governor starting at [`IsolationLevel::Nominal`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_seed(0x9E37_79B9_7F4A_7C15)
    }

    /// Create with an explicit jitter seed (tests pin this for determinism;
    /// production should vary it per device so a city does not synchronise).
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self {
            level: RwLock::new(IsolationLevel::Nominal),
            transports: RwLock::new(HashMap::new()),
            stats: RwLock::new(CadenceStats::default()),
            jitter_seed: RwLock::new(seed),
        }
    }

    /// Update the isolation level that sets the base cadence.
    ///
    /// Moving to a *less* severe level takes effect immediately: anything that
    /// was scheduled far in the future is pulled back in, so a recovery is
    /// never delayed by a stale blackout-era schedule.
    pub fn set_level(&self, level: IsolationLevel, now: Instant) {
        let previous = {
            let mut g = self.level.write();
            let prev = *g;
            *g = level;
            prev
        };
        if level < previous {
            // De-escalation: re-arm everything against the faster cadence.
            let ceiling = base_interval_for(level);
            let mut t = self.transports.write();
            for st in t.values_mut() {
                let capped = now + ceiling;
                if st.next_due > capped {
                    st.next_due = capped;
                }
            }
        }
    }

    /// The isolation level currently governing cadence.
    #[must_use]
    pub fn level(&self) -> IsolationLevel {
        *self.level.read()
    }

    /// Whether `transport` may be probed at `now`.
    ///
    /// Unknown transports are always probeable once — a newly-registered path
    /// must never be held back by another transport's failures.
    pub fn may_probe(&self, transport: &str, now: Instant) -> bool {
        let t = self.transports.read();
        t.get(transport).is_none_or(|st| now >= st.next_due)
    }

    /// Ask permission to probe, recording the outcome in the metrics.
    ///
    /// Returns `true` if the probe should go ahead. This is the method a probe
    /// loop calls; [`ProbeCadence::may_probe`] is the side-effect-free query.
    pub fn try_probe(&self, transport: &str, now: Instant) -> bool {
        let mut t = self.transports.write();
        let st = t
            .entry(transport.to_string())
            .or_insert_with(|| TransportState::new(now));
        if now >= st.next_due {
            st.probes_allowed += 1;
            self.stats.write().allowed += 1;
            true
        } else {
            st.probes_suppressed += 1;
            self.stats.write().suppressed += 1;
            false
        }
    }

    /// Record a failed probe: grow this transport's back-off.
    ///
    /// The delay is `max(level_base, floor * 2^failures)`, capped, then
    /// jittered. The level floor means blackout discipline always applies even
    /// on the first failure at that level.
    pub fn note_failure(&self, transport: &str, now: Instant) {
        let level = *self.level.read();
        let base = base_interval_for(level);
        let jitter_seed = {
            let mut s = self.jitter_seed.write();
            *s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *s
        };

        let mut t = self.transports.write();
        let st = t
            .entry(transport.to_string())
            .or_insert_with(|| TransportState::new(now));
        st.consecutive_failures = st.consecutive_failures.saturating_add(1);

        let shift = st.consecutive_failures.min(MAX_BACKOFF_SHIFT);
        let grown = FLOOR_INTERVAL
            .checked_mul(BACKOFF_FACTOR.saturating_pow(shift))
            .unwrap_or(MAX_INTERVAL);
        // The level's base cadence is a FLOOR, not a ceiling: at
        // ConfirmedIsolation we never probe faster than every 30 s even if the
        // exponential term is still small.
        let chosen = grown.max(base).min(MAX_INTERVAL);
        let delay = Self::jitter(chosen, jitter_seed, transport);
        st.next_due = now + delay;
    }

    /// Record a successful probe.
    ///
    /// Resets back-off to the floor **immediately**. Recovery is never delayed
    /// by prior failures — this is the load-bearing half of the honesty
    /// contract's "instant recovery" promise.
    pub fn note_success(&self, transport: &str, now: Instant) {
        let mut t = self.transports.write();
        let st = t
            .entry(transport.to_string())
            .or_insert_with(|| TransportState::new(now));
        st.consecutive_failures = 0;
        st.next_due = now;
        self.stats.write().resets += 1;
    }

    /// Force a transport to be immediately probeable, bypassing back-off.
    ///
    /// For external wake-ups that invalidate the reason for backing off: a
    /// network-interface change, the user pressing connect, or a mesh peer
    /// reporting that a path is alive. Without this, a device that backed off
    /// to 60 s would sit idle for up to a minute after the network returned.
    pub fn force_due(&self, transport: &str, now: Instant) {
        let mut t = self.transports.write();
        let st = t
            .entry(transport.to_string())
            .or_insert_with(|| TransportState::new(now));
        st.next_due = now;
        self.stats.write().forced += 1;
    }

    /// Force every known transport to be immediately probeable.
    pub fn force_all_due(&self, now: Instant) {
        let mut t = self.transports.write();
        for st in t.values_mut() {
            st.next_due = now;
        }
        let mut s = self.stats.write();
        s.forced += 1;
    }

    /// Time until `transport` may next be probed (zero if due now).
    #[must_use]
    pub fn time_until_due(&self, transport: &str, now: Instant) -> Duration {
        let t = self.transports.read();
        t.get(transport).map_or(Duration::ZERO, |st| {
            st.next_due.saturating_duration_since(now)
        })
    }

    /// Consecutive failures recorded for `transport`.
    #[must_use]
    pub fn failure_count(&self, transport: &str) -> u32 {
        self.transports
            .read()
            .get(transport)
            .map_or(0, |st| st.consecutive_failures)
    }

    /// Snapshot of the cadence metrics.
    #[must_use]
    pub fn stats(&self) -> CadenceStats {
        *self.stats.read()
    }

    /// Number of transports currently tracked.
    #[must_use]
    pub fn tracked_transports(&self) -> usize {
        self.transports.read().len()
    }

    /// Apply ±[`JITTER_PERCENT`] decorrelation to an interval.
    ///
    /// Mixing the transport name into the seed guarantees two transports on the
    /// same device do not fire in lockstep, and the per-instance seed keeps two
    /// devices from doing so either. Never returns zero, so jitter can never
    /// accidentally defeat the back-off it is decorrelating.
    fn jitter(interval: Duration, seed: u64, transport: &str) -> Duration {
        let name_mix = transport.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x1000_0000_01b3)
        });
        let mixed = seed ^ name_mix;
        let span = JITTER_PERCENT * 2; // total window width, in percent
        let offset = mixed % (span + 1); // 0..=span
                                         // Scale to [100-JITTER, 100+JITTER] percent.
        let percent = 100 + offset - JITTER_PERCENT;
        let millis = interval.as_millis() as u64;
        let jittered = millis.saturating_mul(percent) / 100;
        Duration::from_millis(jittered.max(1)).min(MAX_INTERVAL)
    }
}

impl Default for ProbeCadence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn a_fresh_transport_is_immediately_probeable() {
        let c = ProbeCadence::new();
        let now = t0();
        assert!(c.may_probe("webtunnel", now));
        assert!(c.try_probe("webtunnel", now));
        assert_eq!(c.stats().allowed, 1);
        assert_eq!(c.stats().suppressed, 0);
    }

    #[test]
    fn repeated_failures_back_off_monotonically() {
        let c = ProbeCadence::new();
        let now = t0();
        let mut previous = Duration::ZERO;
        for i in 0..6 {
            c.note_failure("webtunnel", now);
            let d = c.time_until_due("webtunnel", now);
            assert!(
                d >= previous || d >= MAX_INTERVAL.mul_f64(0.7),
                "back-off must not shrink on failure {i}: {previous:?} -> {d:?}"
            );
            previous = d;
        }
        assert_eq!(c.failure_count("webtunnel"), 6);
    }

    #[test]
    fn back_off_is_capped_and_never_unbounded() {
        let c = ProbeCadence::new();
        let now = t0();
        for _ in 0..500 {
            c.note_failure("webtunnel", now);
        }
        let d = c.time_until_due("webtunnel", now);
        assert!(d <= MAX_INTERVAL, "interval {d:?} exceeded the cap");
        // Saturating arithmetic must hold at extreme failure counts.
        assert!(c.failure_count("webtunnel") >= 500);
    }

    /// The documented ConfirmedIsolation commitment, enforced as a test.
    #[test]
    fn confirmed_isolation_probes_no_faster_than_every_30_seconds() {
        let c = ProbeCadence::new();
        let now = t0();
        c.set_level(IsolationLevel::ConfirmedIsolation, now);
        c.note_failure("dns-tunnel-masterdns", now);
        let d = c.time_until_due("dns-tunnel-masterdns", now);
        // 30 s minus the jitter window is the fastest permitted.
        let fastest = CONFIRMED_ISOLATION_INTERVAL.mul_f64(1.0 - JITTER_PERCENT as f64 / 100.0);
        assert!(
            d >= fastest,
            "ConfirmedIsolation probed too fast: {d:?} < {fastest:?}"
        );
    }

    #[test]
    fn total_isolation_backs_off_further_than_confirmed() {
        let now = t0();
        let confirmed = ProbeCadence::with_seed(7);
        confirmed.set_level(IsolationLevel::ConfirmedIsolation, now);
        confirmed.note_failure("x", now);

        let total = ProbeCadence::with_seed(7);
        total.set_level(IsolationLevel::TotalIsolation, now);
        total.note_failure("x", now);

        assert!(
            total.time_until_due("x", now) > confirmed.time_until_due("x", now),
            "the hard bound must probe less often than ConfirmedIsolation"
        );
    }

    #[test]
    fn a_retry_storm_is_actually_suppressed() {
        // The battery / footprint claim, measured.
        let c = ProbeCadence::new();
        let now = t0();
        c.set_level(IsolationLevel::ConfirmedIsolation, now);
        // A tight loop hammering the same transport at one instant.
        let mut allowed = 0;
        for _ in 0..1_000 {
            if c.try_probe("webtunnel", now) {
                allowed += 1;
                c.note_failure("webtunnel", now);
            }
        }
        assert_eq!(allowed, 1, "only the first probe of a storm may proceed");
        assert_eq!(c.stats().allowed, 1);
        assert_eq!(c.stats().suppressed, 999);
        assert!(c.stats().suppression_ratio() > 0.99);
    }

    /// The most important property: discipline must never delay recovery.
    #[test]
    fn success_resets_to_the_floor_immediately() {
        let c = ProbeCadence::new();
        let now = t0();
        c.set_level(IsolationLevel::TotalIsolation, now);
        for _ in 0..20 {
            c.note_failure("webtunnel", now);
        }
        assert!(c.time_until_due("webtunnel", now) > Duration::from_secs(10));

        c.note_success("webtunnel", now);
        assert_eq!(
            c.time_until_due("webtunnel", now),
            Duration::ZERO,
            "a success must clear back-off instantly"
        );
        assert!(c.may_probe("webtunnel", now));
        assert_eq!(c.failure_count("webtunnel"), 0);
    }

    #[test]
    fn an_external_wakeup_bypasses_back_off() {
        let c = ProbeCadence::new();
        let now = t0();
        c.set_level(IsolationLevel::TotalIsolation, now);
        for _ in 0..10 {
            c.note_failure("webtunnel", now);
        }
        assert!(!c.may_probe("webtunnel", now));

        // e.g. the OS reports a new network interface.
        c.force_due("webtunnel", now);
        assert!(
            c.may_probe("webtunnel", now),
            "a wake-up must bypass the schedule"
        );
        assert_eq!(c.stats().forced, 1);
    }

    #[test]
    fn de_escalating_the_level_pulls_schedules_forward() {
        // Recovering from a blackout must not leave a 60 s stale schedule.
        let c = ProbeCadence::new();
        let now = t0();
        c.set_level(IsolationLevel::TotalIsolation, now);
        c.note_failure("webtunnel", now);
        let blackout_delay = c.time_until_due("webtunnel", now);
        assert!(blackout_delay > Duration::from_secs(30));

        c.set_level(IsolationLevel::Nominal, now);
        let recovered_delay = c.time_until_due("webtunnel", now);
        assert!(
            recovered_delay <= FLOOR_INTERVAL,
            "de-escalation must pull the schedule in: {recovered_delay:?}"
        );
    }

    #[test]
    fn escalating_the_level_does_not_reset_existing_back_off() {
        let c = ProbeCadence::new();
        let now = t0();
        for _ in 0..8 {
            c.note_failure("webtunnel", now);
        }
        let before = c.time_until_due("webtunnel", now);
        c.set_level(IsolationLevel::ConfirmedIsolation, now);
        let after = c.time_until_due("webtunnel", now);
        assert_eq!(before, after, "escalation must not shorten a back-off");
    }

    #[test]
    fn transports_are_scheduled_independently() {
        let c = ProbeCadence::new();
        let now = t0();
        for _ in 0..10 {
            c.note_failure("dead-transport", now);
        }
        assert!(!c.may_probe("dead-transport", now));
        // A different, previously-unseen transport must not inherit the penalty.
        assert!(
            c.may_probe("fresh-transport", now),
            "one transport's failures must not gate another"
        );
    }

    #[test]
    fn jitter_decorrelates_devices_but_stays_bounded() {
        let now = t0();
        let mut delays = Vec::new();
        for seed in 0..40u64 {
            let c = ProbeCadence::with_seed(seed.wrapping_mul(0x9E37_79B9));
            c.set_level(IsolationLevel::ConfirmedIsolation, now);
            c.note_failure("webtunnel", now);
            delays.push(c.time_until_due("webtunnel", now));
        }
        let distinct: std::collections::HashSet<_> = delays.iter().collect();
        assert!(
            distinct.len() > 1,
            "identical schedules across devices would thunder"
        );
        let lo = CONFIRMED_ISOLATION_INTERVAL.mul_f64(1.0 - JITTER_PERCENT as f64 / 100.0);
        let hi = CONFIRMED_ISOLATION_INTERVAL.mul_f64(1.0 + JITTER_PERCENT as f64 / 100.0);
        for d in &delays {
            assert!(
                *d >= lo && *d <= hi,
                "jittered delay {d:?} left [{lo:?},{hi:?}]"
            );
        }
    }

    #[test]
    fn two_transports_on_one_device_do_not_fire_in_lockstep() {
        let c = ProbeCadence::with_seed(12_345);
        let now = t0();
        c.set_level(IsolationLevel::ConfirmedIsolation, now);
        c.note_failure("webtunnel", now);
        c.note_failure("snowflake", now);
        assert_ne!(
            c.time_until_due("webtunnel", now),
            c.time_until_due("snowflake", now),
            "per-transport schedules must be decorrelated"
        );
    }

    #[test]
    fn every_isolation_level_maps_to_a_sane_interval() {
        // Totality: no level may be unmapped, zero, or above the cap.
        for level in [
            IsolationLevel::Nominal,
            IsolationLevel::Degraded,
            IsolationLevel::Escalated,
            IsolationLevel::ConfirmedIsolation,
            IsolationLevel::TotalIsolation,
        ] {
            let d = base_interval_for(level);
            assert!(d > Duration::ZERO, "{level:?} mapped to zero");
            assert!(d <= MAX_INTERVAL, "{level:?} exceeded the cap");
        }
        // And the ordering must be monotonic in severity.
        assert!(
            base_interval_for(IsolationLevel::Nominal)
                <= base_interval_for(IsolationLevel::Escalated)
        );
        assert!(
            base_interval_for(IsolationLevel::Escalated)
                <= base_interval_for(IsolationLevel::ConfirmedIsolation)
        );
        assert!(
            base_interval_for(IsolationLevel::ConfirmedIsolation)
                <= base_interval_for(IsolationLevel::TotalIsolation)
        );
    }

    #[test]
    fn cadence_is_deterministic_for_a_fixed_seed() {
        let run = || {
            let c = ProbeCadence::with_seed(99);
            let now = t0();
            c.set_level(IsolationLevel::ConfirmedIsolation, now);
            let mut out = Vec::new();
            for _ in 0..5 {
                c.note_failure("webtunnel", now);
                out.push(c.time_until_due("webtunnel", now));
            }
            out
        };
        assert_eq!(run(), run(), "cadence must be fully deterministic");
    }

    #[test]
    fn the_blackout_bridge_is_total_and_conservative() {
        use crate::blackout::IsolationLevel as B;
        // Total: every cause-model level maps somewhere.
        let pairs = [
            (B::Normal, IsolationLevel::Nominal),
            (B::DpiBlocking, IsolationLevel::Degraded),
            (B::RoutingSevered, IsolationLevel::Escalated),
            (B::FullIsolation, IsolationLevel::ConfirmedIsolation),
        ];
        for (cause, expected) in pairs {
            assert_eq!(level_from_blackout(cause), expected, "mapping {cause:?}");
        }
        // Conservative: the cause model can never on its own drive the cadence
        // all the way to the slowest tier, because TotalIsolation additionally
        // requires an out-of-band check the cause model does not perform.
        assert_ne!(
            level_from_blackout(B::FullIsolation),
            IsolationLevel::TotalIsolation
        );
        // Monotonic: worse cause never yields a faster cadence.
        let mut previous = base_interval_for(level_from_blackout(B::Normal));
        for cause in [B::DpiBlocking, B::RoutingSevered, B::FullIsolation] {
            let d = base_interval_for(level_from_blackout(cause));
            assert!(d >= previous, "cadence must not speed up at {cause:?}");
            previous = d;
        }
    }

    #[test]
    fn the_governor_never_claims_anything_about_connectivity() {
        // Structural: this type answers only "may I try again yet?".
        let c = ProbeCadence::new();
        let now = t0();
        c.set_level(IsolationLevel::TotalIsolation, now);
        c.note_failure("webtunnel", now);
        // Suppressing a probe is not a statement that the path is down, and
        // allowing one is not a statement that it is up.
        assert!(!c.may_probe("webtunnel", now));
        c.force_due("webtunnel", now);
        assert!(c.may_probe("webtunnel", now));
        assert_eq!(c.level(), IsolationLevel::TotalIsolation);
    }
}
