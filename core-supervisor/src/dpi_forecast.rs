//! Predictive DPI block forecasting — *act before the block lands*.
//!
//! Every existing decision path in this crate is **reactive**: the
//! [`crate::decider::LocalDecider`] switches protocol *after* the success rate
//! has already collapsed, and [`crate::resilience::ResilienceController`]
//! escalates *after* the primary path is gone. Between the censor's first
//! probe and the user's first stalled request there is a window — typically
//! seconds to tens of seconds on Iranian infrastructure, where a block ramps
//! (a rising RST rate, then TLS truncation, then full drop) rather than
//! landing instantly. **That window is where the user-perceived outage is
//! created, and it is exactly what this module removes.**
//!
//! [`DpiForecaster`] consumes the same observation stream the decider already
//! sees (no new collection path, no duplication) and estimates a **hazard**:
//! the probability that the currently-active transport is blocked within the
//! next `horizon`. When the hazard crosses the pre-warm threshold, the caller
//! (the seamless-continuity controller) is told to warm standby transports
//! *before* the primary dies, so the eventual switch is 0-RTT.
//!
//! ## Why this is not a duplicate of `policy::FallbackEngine`
//!
//! [`crate::policy::FallbackEngine`] answers *"is the current protocol
//! failing right now?"* — a **level** question, from a windowed snapshot.
//! This module answers *"is the current protocol **about to** fail?"* — a
//! **derivative** question, from the trend of that same snapshot over time.
//! The engine keeps sole ownership of the switch/escalate decision;
//! the forecaster never switches anything. It only raises readiness.
//!
//! ## Zero-error contract
//!
//! * Pure, deterministic, allocation-bounded — no ML runtime, no I/O, no clock
//!   dependence beyond the caller-supplied tick.
//! * Every output is a *prediction*, never a claim of connectivity. A forecast
//!   can be wrong; that costs a pre-warmed socket, never a false "Connected".
//! * If it is fed no data, it forecasts `Stable` (fail-safe, never fail-panic).
//! * Deliberately conservative: a hazard is only raised on a **sustained
//!   rising trend**, so a single noisy sample cannot cause churn.

use std::collections::VecDeque;

use parking_lot::RwLock;

use crate::policy::{DEFAULT_SWITCH_THRESHOLD, DPI_SWITCH_RATE};

/// One observation of transport health, folded into the forecaster.
///
/// Mirrors the fields of [`crate::policy::FailureSignature`] the decider
/// already computes, so the caller passes what it has — no new telemetry.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct HealthSample {
    /// Windowed success rate in `[0, 1]`.
    pub success_rate: f64,
    /// Windowed TCP-RST injection rate in `[0, 1]`.
    pub tcp_rst_rate: f64,
    /// Windowed TLS-truncation rate in `[0, 1]`.
    pub tls_trunc_rate: f64,
    /// Windowed DNS-anomaly rate in `[0, 1]`.
    pub dns_anomaly_rate: f64,
    /// Observed round-trip time in milliseconds (0 = unknown).
    pub rtt_ms: u32,
}

impl HealthSample {
    /// A fully-healthy sample (used as the neutral seed).
    #[must_use]
    pub fn healthy() -> Self {
        Self {
            success_rate: 1.0,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
            rtt_ms: 40,
        }
    }

    /// Instantaneous "pressure": **how far this sample has travelled toward
    /// the point at which the reactive engine would act**, where `1.0` means
    /// "the reactive engine trips right now".
    ///
    /// Calibrating against [`crate::policy::DPI_SWITCH_RATE`] and
    /// [`crate::policy::DEFAULT_SWITCH_THRESHOLD`] — rather than inventing a
    /// second, independent scale — is what makes the forecast *comparable* to
    /// the reactive decision instead of merely correlated with it. If those
    /// thresholds are ever retuned, this layer follows automatically and the
    /// two can never silently drift apart.
    ///
    /// The maximum (not the sum) of the independent progress ratios is used:
    /// the reactive engine trips when **any single** condition is met, so the
    /// closest one is the one that matters.
    #[must_use]
    pub fn pressure(&self) -> f64 {
        let dpi = self
            .tcp_rst_rate
            .clamp(0.0, 1.0)
            .max(self.tls_trunc_rate.clamp(0.0, 1.0));
        // Progress toward the DPI-rate trip point.
        let dpi_progress = dpi / DPI_SWITCH_RATE;
        // Progress toward the success-rate trip point.
        let loss = 1.0 - self.success_rate.clamp(0.0, 1.0);
        let loss_budget = (1.0 - DEFAULT_SWITCH_THRESHOLD).max(f64::EPSILON);
        let loss_progress = loss / loss_budget;
        // DNS anomaly is a whole-network signal that bypasses protocol switching
        // entirely (it escalates), so it counts at its own trip scale.
        let dns_progress = self.dns_anomaly_rate.clamp(0.0, 1.0) / crate::policy::DNS_ESCALATE_RATE;

        dpi_progress
            .max(loss_progress)
            .max(dns_progress)
            .clamp(0.0, 1.0)
    }
}

/// What the forecaster believes is about to happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forecast {
    /// No meaningful censorship pressure or trend. Nothing to do.
    Stable,
    /// Pressure is rising but a block is not imminent. Keep watching.
    Rising,
    /// A block is likely inside the horizon — **pre-warm standby transports
    /// now** so the eventual switch costs zero round-trips.
    PrewarmAdvised,
    /// A block is highly likely and imminent — switch pre-emptively onto an
    /// already-warm standby *before* the primary is lost.
    SwitchAdvised,
}

impl Forecast {
    /// Numeric urgency (0 = Stable … 3 = `SwitchAdvised`).
    #[must_use]
    pub fn urgency(self) -> u8 {
        match self {
            Self::Stable => 0,
            Self::Rising => 1,
            Self::PrewarmAdvised => 2,
            Self::SwitchAdvised => 3,
        }
    }

    /// Whether standby transports should be held hot at this urgency.
    #[must_use]
    pub fn wants_prewarm(self) -> bool {
        self.urgency() >= Self::PrewarmAdvised.urgency()
    }
}

/// A full forecast report — the hazard plus the reasoning behind it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ForecastReport {
    /// The recommended action.
    pub forecast: Forecast,
    /// Estimated probability of a block inside the horizon, in `[0, 1]`.
    pub hazard: f64,
    /// Smoothed censorship pressure in `[0, 1]`.
    pub pressure: f64,
    /// Per-tick slope of the smoothed pressure (positive = worsening).
    pub trend: f64,
    /// How many observations back this report (0 ⇒ `Stable`, fail-safe).
    pub samples: usize,
}

impl ForecastReport {
    /// The neutral, no-data report. Never claims risk it cannot justify.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            forecast: Forecast::Stable,
            hazard: 0.0,
            pressure: 0.0,
            trend: 0.0,
            samples: 0,
        }
    }
}

/// Hazard at/above which standby transports are pre-warmed.
pub const PREWARM_HAZARD: f64 = 0.45;
/// Hazard at/above which a pre-emptive switch is advised.
pub const SWITCH_HAZARD: f64 = 0.75;
/// Minimum observations before any non-`Stable` forecast (anti-flap).
pub const MIN_SAMPLES: usize = 4;
/// EWMA smoothing factor for pressure (higher = more reactive).
const ALPHA: f64 = 0.4;
/// Bounded history length — memory is O(1) regardless of uptime.
const HISTORY: usize = 16;

struct Inner {
    /// Bounded ring of recent raw pressures (for trend estimation).
    history: VecDeque<f64>,
    /// EWMA-smoothed pressure.
    smoothed: f64,
    /// Whether the EWMA has been seeded yet.
    seeded: bool,
    /// Total observations folded in (monotonic; for metrics).
    observed: u64,
    /// Number of times a `PrewarmAdvised`-or-worse forecast was produced.
    prewarm_signals: u64,
    /// Number of times a `SwitchAdvised` forecast was produced.
    switch_signals: u64,
}

/// The predictive DPI forecaster. Thread-safe; cheap to share behind an `Arc`.
pub struct DpiForecaster {
    inner: RwLock<Inner>,
}

impl DpiForecaster {
    /// Create an empty forecaster. With no data it forecasts [`Forecast::Stable`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                history: VecDeque::with_capacity(HISTORY),
                smoothed: 0.0,
                seeded: false,
                observed: 0,
                prewarm_signals: 0,
                switch_signals: 0,
            }),
        }
    }

    /// Fold one observation in and return the updated forecast.
    ///
    /// This is the only mutation point. It is deterministic: the same sequence
    /// of samples always yields the same sequence of reports.
    pub fn observe(&self, sample: &HealthSample) -> ForecastReport {
        let mut g = self.inner.write();
        let p = sample.pressure();

        if g.seeded {
            g.smoothed = ALPHA * p + (1.0 - ALPHA) * g.smoothed;
        } else {
            g.smoothed = p;
            g.seeded = true;
        }
        if g.history.len() == HISTORY {
            g.history.pop_front();
        }
        g.history.push_back(p);
        g.observed += 1;

        let samples = g.history.len();
        let trend = Self::slope(&g.history);
        let smoothed = g.smoothed;
        let hazard = Self::hazard(smoothed, trend);

        let forecast = if samples < MIN_SAMPLES {
            // Fail-safe: never predict a block we cannot justify with data.
            Forecast::Stable
        } else if hazard >= SWITCH_HAZARD {
            Forecast::SwitchAdvised
        } else if hazard >= PREWARM_HAZARD {
            Forecast::PrewarmAdvised
        } else if trend > 0.0 && smoothed > 0.05 {
            Forecast::Rising
        } else {
            Forecast::Stable
        };

        match forecast {
            Forecast::SwitchAdvised => {
                g.switch_signals += 1;
                g.prewarm_signals += 1;
            }
            Forecast::PrewarmAdvised => g.prewarm_signals += 1,
            _ => {}
        }

        ForecastReport {
            forecast,
            hazard,
            pressure: smoothed,
            trend,
            samples,
        }
    }

    /// Current forecast without folding in a new observation.
    #[must_use]
    pub fn current(&self) -> ForecastReport {
        let g = self.inner.read();
        let samples = g.history.len();
        if samples == 0 {
            return ForecastReport::unknown();
        }
        let trend = Self::slope(&g.history);
        let hazard = Self::hazard(g.smoothed, trend);
        let forecast = if samples < MIN_SAMPLES {
            Forecast::Stable
        } else if hazard >= SWITCH_HAZARD {
            Forecast::SwitchAdvised
        } else if hazard >= PREWARM_HAZARD {
            Forecast::PrewarmAdvised
        } else if trend > 0.0 && g.smoothed > 0.05 {
            Forecast::Rising
        } else {
            Forecast::Stable
        };
        ForecastReport {
            forecast,
            hazard,
            pressure: g.smoothed,
            trend,
            samples,
        }
    }

    /// Reset to the neutral state (called on a confirmed recovery, so a past
    /// blackout cannot keep the forecast pessimistic forever).
    pub fn reset(&self) {
        let mut g = self.inner.write();
        g.history.clear();
        g.smoothed = 0.0;
        g.seeded = false;
    }

    /// Total observations folded in since construction.
    #[must_use]
    pub fn observed_count(&self) -> u64 {
        self.inner.read().observed
    }

    /// How many times a pre-warm (or stronger) signal was raised.
    #[must_use]
    pub fn prewarm_signal_count(&self) -> u64 {
        self.inner.read().prewarm_signals
    }

    /// How many times a pre-emptive switch was advised.
    #[must_use]
    pub fn switch_signal_count(&self) -> u64 {
        self.inner.read().switch_signals
    }

    /// Least-squares slope of the pressure history, per tick.
    ///
    /// Returns 0.0 for fewer than two points (no trend is inferable).
    fn slope(history: &VecDeque<f64>) -> f64 {
        let n = history.len();
        if n < 2 {
            return 0.0;
        }
        let n_f = n as f64;
        let mean_x = (n_f - 1.0) / 2.0;
        let mean_y = history.iter().sum::<f64>() / n_f;
        let mut num = 0.0;
        let mut den = 0.0;
        for (i, y) in history.iter().enumerate() {
            let dx = i as f64 - mean_x;
            num += dx * (y - mean_y);
            den += dx * dx;
        }
        if den <= f64::EPSILON {
            0.0
        } else {
            num / den
        }
    }

    /// Combine smoothed level and trend into a hazard in `[0, 1]`.
    ///
    /// Because `pressure` is expressed as *progress toward the reactive trip
    /// point*, the projection has a direct operational meaning: it is where
    /// that progress will be [`PROJECTION_TICKS`] ticks from now if the
    /// current trend holds. A hazard near `1.0` therefore reads as "the
    /// reactive engine is about to trip" — which is precisely when a standby
    /// transport must already be warm.
    ///
    /// The level says how bad it is now; the trend says how fast it is getting
    /// worse. A high level with a flat/falling trend is a *steady-state* bad
    /// link (the decider already handles that). A moderate level with a steep
    /// rising trend is the signature of a block *landing* — the projection
    /// term is what catches it early.
    fn hazard(smoothed: f64, trend: f64) -> f64 {
        let projected = smoothed + trend * PROJECTION_TICKS;
        let level_term = 0.55 * smoothed.clamp(0.0, 1.0);
        let projection_term = 0.45 * projected.clamp(0.0, 1.0);
        (level_term + projection_term).clamp(0.0, 1.0)
    }
}

/// How many ticks ahead the hazard projects the current trend.
///
/// This is the forecast horizon. It is deliberately shorter than the
/// reactive engine's `min_samples` window (20), which is what gives the
/// forecaster its head start — see the `predicts_strictly_before_the_real_
/// reactive_engine_reacts` test, which measures that lead against the real
/// [`crate::policy::FallbackEngine`] rather than a proxy threshold.
const PROJECTION_TICKS: f64 = 8.0;

impl Default for DpiForecaster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ramping(step: usize) -> HealthSample {
        // Model an Iranian block ramp: RST injection climbs first, then TLS
        // truncation, and success decays last.
        let t = step as f64;
        HealthSample {
            success_rate: (1.0 - 0.09 * t).max(0.0),
            tcp_rst_rate: (0.10 * t).min(1.0),
            tls_trunc_rate: (0.07 * t).min(1.0),
            dns_anomaly_rate: 0.0,
            rtt_ms: 60 + 20 * step as u32,
        }
    }

    #[test]
    fn no_data_is_stable_and_never_panics() {
        let f = DpiForecaster::new();
        let r = f.current();
        assert_eq!(r.forecast, Forecast::Stable);
        assert_eq!(r.samples, 0);
        assert!(r.hazard.abs() < f64::EPSILON);
    }

    #[test]
    fn steady_healthy_traffic_never_raises_a_forecast() {
        let f = DpiForecaster::new();
        let mut last = ForecastReport::unknown();
        for _ in 0..24 {
            last = f.observe(&HealthSample::healthy());
        }
        assert_eq!(last.forecast, Forecast::Stable);
        assert!(last.hazard < PREWARM_HAZARD, "hazard was {}", last.hazard);
        assert_eq!(f.prewarm_signal_count(), 0);
    }

    #[test]
    fn a_ramping_block_is_predicted_while_the_link_still_works() {
        let f = DpiForecaster::new();
        let mut prewarm_at = None;
        for step in 0..10 {
            let s = ramping(step);
            let r = f.observe(&s);
            if prewarm_at.is_none() && r.forecast.wants_prewarm() {
                prewarm_at = Some((step, s.success_rate));
                break;
            }
        }
        let (step, success_rate) = prewarm_at.expect("a ramping block must be predicted");
        // The point of pre-warming: it must happen while the primary path is
        // still carrying real traffic, so the standby is hot before the cut.
        assert!(
            success_rate > 0.0,
            "pre-warm fired at step {step} only after total loss — too late"
        );
        assert!(f.prewarm_signal_count() > 0);
    }

    /// The load-bearing claim of this module, measured against the **real**
    /// reactive path rather than a stand-in threshold: during an Iranian block
    /// ramp, the forecaster must advise pre-warming *strictly before*
    /// [`crate::policy::FallbackEngine`] — driven by the real
    /// [`crate::decider::LocalDecider`] — decides to switch. That gap is the
    /// window in which a standby transport is warmed, and it is exactly the
    /// outage the user would otherwise feel.
    #[test]
    fn predicts_strictly_before_the_real_reactive_engine_reacts() {
        use crate::decider::{FailKind, LocalDecider};
        use crate::policy::{Decision, FallbackEngine};

        let f = DpiForecaster::new();
        let mut decider = LocalDecider::new("reality-vision", 64, FallbackEngine::default());

        let mut forecast_tick = None;
        let mut reactive_tick = None;

        // One tick == one probe outcome. Crucially, BOTH paths are driven from
        // the *same* windowed signature the decider itself computes — no
        // separate telemetry, no advantage handed to the forecaster.
        for tick in 0..200usize {
            // A block ramp: RST injection becomes steadily more frequent.
            let rst_every = match tick {
                0..=19 => 0,  // clean
                20..=59 => 5, // 1-in-5 probes RST
                60..=99 => 3, // 1-in-3
                _ => 2,       // every other probe
            };
            if rst_every > 0 && tick % rst_every == 0 {
                decider.observe_failure(FailKind::RstInjection);
            } else {
                decider.observe_success();
            }

            // The forecaster consumes exactly the decider's own signature.
            let sig = decider.signature();
            let r = f.observe(&HealthSample {
                success_rate: sig.success_rate,
                tcp_rst_rate: sig.tcp_rst_rate,
                tls_trunc_rate: sig.tls_trunc_rate,
                dns_anomaly_rate: sig.dns_anomaly_rate,
                rtt_ms: 0,
            });

            if forecast_tick.is_none() && r.forecast.wants_prewarm() {
                forecast_tick = Some(tick);
            }
            if reactive_tick.is_none() && !matches!(decider.decide(), Decision::Keep(_)) {
                reactive_tick = Some(tick);
            }
            if forecast_tick.is_some() && reactive_tick.is_some() {
                break;
            }
        }

        let forecast_tick = forecast_tick.expect("forecaster must predict the ramp");
        let reactive_tick = reactive_tick.expect("reactive engine must eventually react");
        assert!(
            forecast_tick < reactive_tick,
            "forecaster gave no lead time: predicted at tick {forecast_tick}, \
             reactive engine acted at tick {reactive_tick}"
        );
    }

    #[test]
    fn a_hard_sustained_block_escalates_to_switch_advised() {
        let f = DpiForecaster::new();
        let mut seen_switch = false;
        for _ in 0..12 {
            let r = f.observe(&HealthSample {
                success_rate: 0.0,
                tcp_rst_rate: 1.0,
                tls_trunc_rate: 1.0,
                dns_anomaly_rate: 1.0,
                rtt_ms: 0,
            });
            if r.forecast == Forecast::SwitchAdvised {
                seen_switch = true;
            }
        }
        assert!(
            seen_switch,
            "a total block must advise a pre-emptive switch"
        );
        assert!(f.switch_signal_count() > 0);
    }

    #[test]
    fn a_single_noisy_sample_cannot_cause_churn() {
        let f = DpiForecaster::new();
        for _ in 0..8 {
            f.observe(&HealthSample::healthy());
        }
        // One catastrophic outlier in an otherwise healthy stream.
        let r = f.observe(&HealthSample {
            success_rate: 0.0,
            tcp_rst_rate: 1.0,
            tls_trunc_rate: 1.0,
            dns_anomaly_rate: 1.0,
            rtt_ms: 0,
        });
        assert!(
            !matches!(r.forecast, Forecast::SwitchAdvised),
            "one outlier must not trigger a pre-emptive switch (got {:?})",
            r.forecast
        );
    }

    #[test]
    fn recovery_reset_clears_pessimism() {
        let f = DpiForecaster::new();
        for step in 0..10 {
            f.observe(&ramping(step));
        }
        assert!(f.current().hazard > 0.0);
        f.reset();
        let r = f.current();
        assert_eq!(r.forecast, Forecast::Stable);
        assert_eq!(r.samples, 0);
        // Monotonic counters survive a reset (they are lifetime metrics).
        assert_eq!(f.observed_count(), 10);
    }

    #[test]
    fn forecast_is_deterministic_for_the_same_input_sequence() {
        let run = || {
            let f = DpiForecaster::new();
            (0..10).map(|s| f.observe(&ramping(s))).collect::<Vec<_>>()
        };
        assert_eq!(run(), run(), "forecasting must be fully deterministic");
    }

    #[test]
    fn hazard_and_pressure_are_always_in_range() {
        let f = DpiForecaster::new();
        // Adversarial inputs: out-of-range rates must be clamped, not trusted.
        for i in 0..40 {
            let r = f.observe(&HealthSample {
                success_rate: if i % 2 == 0 { -5.0 } else { 9.0 },
                tcp_rst_rate: 12.0,
                tls_trunc_rate: -3.0,
                dns_anomaly_rate: f64::from(i),
                rtt_ms: u32::MAX,
            });
            assert!((0.0..=1.0).contains(&r.hazard), "hazard {}", r.hazard);
            assert!((0.0..=1.0).contains(&r.pressure), "pressure {}", r.pressure);
        }
    }

    #[test]
    fn memory_is_bounded_regardless_of_uptime() {
        let f = DpiForecaster::new();
        for i in 0..10_000 {
            f.observe(&ramping(i % 6));
        }
        assert_eq!(f.current().samples, HISTORY);
        assert_eq!(f.observed_count(), 10_000);
    }

    #[test]
    fn forecast_never_asserts_connectivity() {
        // Structural guarantee: the forecast enum has no "Connected" state.
        // The only outputs are readiness advisories.
        for fc in [
            Forecast::Stable,
            Forecast::Rising,
            Forecast::PrewarmAdvised,
            Forecast::SwitchAdvised,
        ] {
            assert!(fc.urgency() <= 3);
        }
        assert!(!Forecast::Stable.wants_prewarm());
        assert!(!Forecast::Rising.wants_prewarm());
        assert!(Forecast::PrewarmAdvised.wants_prewarm());
        assert!(Forecast::SwitchAdvised.wants_prewarm());
    }
}
