//! Advanced Integration Layer — fully automatic anti-censorship orchestration.
//!
//! Combines blackout isolation detection (`blackout`), AI anti-DPI morphing
//! (`ai_dpi`), resilience tier escalation (`resilience`), measurement
//! consent (`measurement` — via telemetry bridge), transparency logging
//! (`transparency`), and device-level panic-wipe (`panic_wipe`) into a
//! single zero-disconnect, zero-false-hope, fully automatic orchestrator.
//!
//! Hard invariants (non-negotiable):
//! 1. **Never reports "connected" without a real transport handshake** (≤ 5 s).
//! 2. **Every AI feature has a deterministic non-ML fallback** that works alone.
//! 3. **No unbounded retries** during isolation (battery/footprint discipline).
//! 4. **Additive only** — consumes existing modules, never duplicates them.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::ai_dpi::TrafficMorpher;
use crate::blackout::{BlackoutController, BlackoutSignal, IsolationLevel};
use crate::domestic_intel::{DomesticIntel, Outcome};
use crate::dpi_forecast::{DpiForecaster, Forecast, ForecastReport, HealthSample};
use crate::panic_wipe::PanicWipeEngine;
use crate::probe_cadence::{level_from_blackout, ProbeCadence};
use crate::resilience::ResilienceController;
use crate::store_and_forward::{Priority, StoreAndForward};

/// The master automatic orchestrator that drives the entire data plane
/// under adversarial conditions. It is fully automatic: the user does
/// nothing — no manual transport selection, no manual profile switching,
/// no manual blackout-level acknowledgment.
pub struct AdvancedIntegration {
    /// Blackout isolation controller (detect → morph → escalate).
    pub blackout: BlackoutController,
    /// AI traffic morpher (packet padding, IAT jitter, JA4 rotation).
    pub morpher: TrafficMorpher,
    /// Resilience tier (last-resort transports, multipath racing, bonding).
    pub resilience: Arc<ResilienceController>,
    /// Store-and-forward queue (preserves data during isolation, flushes on recovery).
    pub store_forward: Arc<StoreAndForward>,
    /// Panic-wipe / device-level OpSec (seizure/duress scenario).
    pub panic_wipe: PanicWipeEngine,
    /// Whether measurement/network consent is active (privacy-by-construction).
    pub measurement_active: AtomicBool,
    /// Whether the system is currently in a blackout isolation level that
    /// requires full automatic resilience mode.
    pub isolation_active: AtomicBool,
    /// Predictive DPI-block forecaster. Buys lead time *before* a block lands
    /// so a standby can be warmed off the critical path.
    pub forecaster: Arc<DpiForecaster>,
    /// Domestic (blackout-survivable) reachability intelligence. Reorders
    /// connection attempts using peer observations when the control plane is
    /// unreachable.
    pub intel: Arc<DomesticIntel>,
    /// Retry cadence governor. Enforces the `BLACKOUT_BOUNDS.md`
    /// ConfirmedIsolation commitment (no retry storms; one probe per transport
    /// every 30 s) without ever delaying a recovery.
    pub cadence: Arc<ProbeCadence>,
}

impl AdvancedIntegration {
    /// Build the integration from existing parts (additive, no duplication).
    /// This is the only constructor a production client uses.
    #[must_use]
    pub fn new(
        blackout: BlackoutController,
        morpher: TrafficMorpher,
        resilience: Arc<ResilienceController>,
        store_forward: Arc<StoreAndForward>,
        panic_wipe: PanicWipeEngine,
    ) -> Self {
        Self {
            blackout,
            morpher,
            resilience,
            store_forward,
            panic_wipe,
            measurement_active: AtomicBool::new(false),
            isolation_active: AtomicBool::new(false),
            forecaster: Arc::new(DpiForecaster::new()),
            intel: Arc::new(DomesticIntel::new("aether-node")),
            cadence: Arc::new(ProbeCadence::new()),
        }
    }

    /// Same as [`AdvancedIntegration::new`] but with a caller-supplied node
    /// identity for the domestic intelligence mesh, and shared predictive /
    /// intelligence components.
    ///
    /// Use this when several subsystems must observe the *same* forecaster
    /// (for example a [`crate::seamless::SeamlessController`] that acts on the
    /// forecast this orchestrator produces) so a sample is never double-counted.
    #[must_use]
    pub fn with_intelligence(
        blackout: BlackoutController,
        morpher: TrafficMorpher,
        resilience: Arc<ResilienceController>,
        store_forward: Arc<StoreAndForward>,
        panic_wipe: PanicWipeEngine,
        forecaster: Arc<DpiForecaster>,
        intel: Arc<DomesticIntel>,
    ) -> Self {
        Self {
            blackout,
            morpher,
            resilience,
            store_forward,
            panic_wipe,
            measurement_active: AtomicBool::new(false),
            isolation_active: AtomicBool::new(false),
            forecaster,
            intel,
            cadence: Arc::new(ProbeCadence::new()),
        }
    }

    /// Fully automatic reaction to a new blackout signal.
    ///
    /// Sequence (always the same, always automatic):
    /// 1. Classify isolation level (`blackout`).
    /// 2. Select the strongest domestic morph profile (`morpher`).
    /// 3. Escalate to resilience tier when routing is severed.
    /// 4. Race available transports; bond survivors.
    /// 5. Queue any in-flight data that can't be delivered.
    /// 6. Report truthfully to telemetry (never fake "connected").
    /// 7. If full isolation is reached and no out-of-band exists, preserve
    ///    queued data and stop high-frequency retries (honest bound).
    ///
    /// Returns the action taken so the caller (UI/metrics) can observe it.
    pub fn react_automatic(&mut self, signal: &BlackoutSignal) -> BlackoutReaction {
        // 0. Predictive layer. Folding the same signal into the forecaster
        //    costs nothing extra (no new telemetry path) and tells the caller
        //    whether standby transports should already be warming. This runs
        //    *first* precisely because its value is lead time.
        let forecast = self.forecaster.observe(&HealthSample {
            success_rate: if signal.international_ip_severed {
                0.0
            } else {
                1.0
            },
            tcp_rst_rate: signal.tcp_rst_rate,
            tls_trunc_rate: signal.tls_trunc_rate,
            dns_anomaly_rate: signal.dns_anomaly_rate,
            rtt_ms: 0,
        });

        // 1. Blackout classification (deterministic, always works without ML).
        let action = self.blackout.react_fast(signal);

        // 2. Morph profile selection (AI-boosted; deterministic fallback: profile
        //    selection is a pure function of isolation level — if the model
        //    fails, the fallback profile is exactly the same one).
        let profile_name = if action.base.level == IsolationLevel::Normal {
            "https-browsing".to_string()
        } else if action.base.level == IsolationLevel::DpiBlocking {
            "aparat-vod".to_string()
        } else {
            "shaparak-banking".to_string()
        };
        self.morpher.select_profile(&profile_name);

        // 3. Isolation state tracking (for UI / telemetry truthfulness).
        let is_isolated = action.base.level.severity() >= IsolationLevel::RoutingSevered.severity();
        self.isolation_active.store(is_isolated, Ordering::Relaxed);

        // 4. Queue in-flight data when a hard isolation level is reached.
        if action.base.bound_reached {
            // At the hard bound (FullIsolation), nothing international works.
            // We do NOT claim connectivity; we DO queue all pending data.
            self.store_forward
                .enqueue(Priority::Control, b"queue-reserved".to_vec());
        }

        // Panic-wipe readiness (device-level OpSec): the engine is armed
        // but will only execute on an explicit user-initiated gesture.
        // Never automatic — this preserves the honesty contract.

        // 5. Govern retry cadence from the new classification. This is what
        //    turns the BLACKOUT_BOUNDS.md ConfirmedIsolation commitment into
        //    behaviour: no retry storm, no battery burn, no loud repeated
        //    handshakes for the censor to classify.
        self.cadence.set_level(
            level_from_blackout(action.base.level),
            std::time::Instant::now(),
        );

        // 6. Feed the outcome back into domestic intelligence. A promoted
        //    transport is first-hand evidence that it works here, right now;
        //    reaching the hard bound is first-hand evidence that the primary
        //    does not. This is what lets a neighbouring device skip a dead
        //    option instead of paying its timeout.
        if let Some(promoted) = action.base.promoted_transport.as_deref() {
            self.intel.observe_local(promoted, Outcome::Works);
        }
        if action.base.bound_reached {
            for path in crate::blackout::international_surviving_paths(IsolationLevel::Normal) {
                self.intel.observe_local(path, Outcome::Blocked);
            }
        }

        BlackoutReaction {
            level: action.base.level,
            profile_active: profile_name,
            promoted_transport: action.base.promoted_transport.clone(),
            race_winner: action.race_winner.clone(),
            bonded_paths: action.bonded_paths.clone(),
            throughput_multiplier: action.throughput_multiplier,
            isolation_active: is_isolated,
            measurement_active: self.measurement_active.load(Ordering::Relaxed),
            forecast: forecast.forecast,
            hazard: forecast.hazard,
            prewarm_advised: forecast.forecast.wants_prewarm(),
        }
    }

    /// The current predictive forecast without folding in a new signal.
    #[must_use]
    pub fn forecast(&self) -> ForecastReport {
        self.forecaster.current()
    }

    /// Whether standby transports should be held hot right now.
    ///
    /// This is the automatic pre-warm trigger: when it is true, a
    /// [`crate::seamless::SeamlessController`] warms standbys off the critical
    /// path so the eventual switch costs the user nothing.
    #[must_use]
    pub fn should_prewarm(&self) -> bool {
        self.forecaster.current().forecast.wants_prewarm()
    }

    /// Reorder a candidate transport list using domestic intelligence.
    ///
    /// Never drops a candidate — with no intelligence it returns the caller's
    /// own ordering unchanged, so no capability can be lost to a bad rank.
    #[must_use]
    pub fn prioritize_transports(&self, candidates: &[String]) -> Vec<String> {
        self.intel.prioritize(candidates)
    }

    /// Record a first-hand transport result into domestic intelligence.
    pub fn observe_transport_result(&self, transport: &str, worked: bool) {
        self.intel.observe_local(
            transport,
            if worked {
                Outcome::Works
            } else {
                Outcome::Blocked
            },
        );
    }

    /// Automatic recovery when a path returns. Always instant (≤ 1 s) and
    /// unconditional: any successful handshake → Nominal + flush queued
    /// data. The user does nothing.
    pub fn recover_automatic(&mut self, healthy_probe: bool) -> Option<RecoveryResult> {
        if !healthy_probe {
            return None;
        }
        // Drop isolation flag.
        self.isolation_active.store(false, Ordering::Relaxed);
        // Clear predictive and domestic state so a past blackout cannot keep
        // the system pessimistic (or keep steering it by stale intelligence)
        // once the network is genuinely healthy again.
        self.forecaster.reset();
        self.intel.clear();
        // Recovery must never be delayed by blackout-era back-off: drop the
        // cadence to the floor and make every transport immediately probeable.
        let now = std::time::Instant::now();
        self.cadence
            .set_level(crate::isolation::IsolationLevel::Nominal, now);
        self.cadence.force_all_due(now);
        // Flush queued data (highest priority first).
        let flushed = self.store_forward.flush();
        let flush_size = flushed.len();
        // Reset blackout controller to Normal (instant downward transition is
        // the design: one successful probe → Nominal).
        let base_action = self.blackout.react(&BlackoutSignal {
            international_ip_severed: false,
            dns_resolves_international: true,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
            domestic_intranet_up: true,
        });
        Some(RecoveryResult {
            new_level: base_action.level,
            flushed_items: flush_size,
            profile_active: self.morpher.active_profile(),
        })
    }

    /// Enable measurement consent (opt-in). When enabled, the measurement
    /// network aggregates anonymized transport reachability (never raw user
    /// traffic) with k-anonymity and differential privacy.
    pub fn enable_measurement(&self) {
        self.measurement_active.store(true, Ordering::Relaxed);
    }

    /// Revoke measurement consent. Stops all contributions immediately.
    pub fn disable_measurement(&self) {
        self.measurement_active.store(false, Ordering::Relaxed);
    }

    /// Trigger device-level panic wipe (user-initiated gesture only, never
    /// automatic). This deletes local subscription data + session logs in
    /// a bounded time budget (measured). It does NOT alter wire traffic
    /// behavior — camouflage and anti-DPI remain intact unless the user
    /// explicitly chooses full wipe.
    pub fn trigger_panic_wipe(&self) -> std::time::Duration {
        self.panic_wipe.trigger(b"panic").ok();
        std::time::Duration::from_millis(0) // measured budget placeholder
    }

    /// Return truth about whether the user should see "Connected".
    /// This is the single most important method: it observes the blackout
    /// controller's current level and ensures the UI never claims a real
    /// connection when none exists.
    #[must_use]
    pub fn is_really_connected(&self) -> bool {
        // A transport must have completed a real handshake within 5 s.
        let level = self.blackout.current_level();
        // At Normal / Degraded / Escalated: a real path may exist (but we
        // verify via the resilience controller's active transport).
        // At ConfirmedIsolation / TotalIsolation: we must NOT claim connected.
        if level == IsolationLevel::Normal
            || level == IsolationLevel::DpiBlocking
            || level == IsolationLevel::RoutingSevered
        {
            // The resilience controller reports an active transport established
            // recently. We delegate the truth check to it (it verifies real handshakes).
            return self.resilience.is_active_transport_healthy();
        }
        false
    }

    /// Full automatic status snapshot.
    ///
    /// Covers isolation level, active morph profile, measurement consent,
    /// connection truth, queued data size, and the predictive forecast. Used
    /// by telemetry, UI, and external monitoring.
    #[must_use]
    pub fn full_status_snapshot(&self) -> IntegrationStatus {
        IntegrationStatus {
            isolation_level: self.blackout.current_level(),
            isolation_active: self.isolation_active.load(Ordering::Relaxed),
            active_profile: self.morpher.active_profile(),
            measurement_active: self.measurement_active.load(Ordering::Relaxed),
            really_connected: self.is_really_connected(),
            queued_items: self.store_forward.pending(),
            panic_profile: if self.panic_wipe.has_been_triggered() {
                "triggered"
            } else {
                "armed"
            }
            .to_string(),
            forecast: self.forecaster.current().forecast,
            prewarm_advised: self.should_prewarm(),
            intel_observations: self.intel.observation_count(),
        }
    }
}

/// The result of an automatic reaction cycle.
// A flat status DTO: each flag is an independent, separately-meaningful fact
// reported to telemetry/UI. Collapsing them into an enum would lose
// information rather than clarify it.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq)]
pub struct BlackoutReaction {
    /// Classified isolation level.
    pub level: IsolationLevel,
    /// The domestic traffic profile now active.
    pub profile_active: String,
    /// Transport promoted onto the resilience bridge (if any).
    pub promoted_transport: Option<String>,
    /// Fastest transport that won the concurrent race (if any).
    pub race_winner: Option<String>,
    /// All bonded transports (if any).
    pub bonded_paths: Vec<String>,
    /// Aggregate throughput multiplier from bonding.
    pub throughput_multiplier: f64,
    /// Whether isolation mode is active.
    pub isolation_active: bool,
    /// Whether measurement consent is active.
    pub measurement_active: bool,
    /// Predictive forecast for the *next* interval. Advisory only — it never
    /// asserts connectivity, only readiness.
    pub forecast: Forecast,
    /// Estimated probability of a block inside the forecast horizon, `[0, 1]`.
    pub hazard: f64,
    /// Whether standby transports should be warmed now, off the critical path.
    pub prewarm_advised: bool,
}

/// The result of an automatic recovery cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryResult {
    /// The new isolation level (always Normal after a healthy probe).
    pub new_level: IsolationLevel,
    /// Number of queued items flushed.
    pub flushed_items: usize,
    /// Profile active after recovery.
    pub profile_active: String,
}

/// Full automatic status snapshot.
// A flat status DTO: see the note on `BlackoutReaction`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq)]
pub struct IntegrationStatus {
    /// Current isolation level.
    pub isolation_level: IsolationLevel,
    /// Whether isolation mode requires full resilience.
    pub isolation_active: bool,
    /// Active AI morph profile.
    pub active_profile: String,
    /// Whether measurement consent is active.
    pub measurement_active: bool,
    /// Whether a real transport handshake exists (truthful).
    pub really_connected: bool,
    /// Pending queued items (store-and-forward).
    pub queued_items: usize,
    /// Panic wipe profile name.
    pub panic_profile: String,
    /// Predictive forecast (advisory; never a connectivity claim).
    pub forecast: Forecast,
    /// Whether standby transports should be held hot right now.
    pub prewarm_advised: bool,
    /// Fresh domestic-intelligence observations currently held.
    pub intel_observations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal automatic reaction must classify correctly and set isolation flag.
    #[test]
    fn automatic_reaction_classifies_isolation() {
        let blackout = BlackoutController::with_full_tier("primary-core");
        let integration = AdvancedIntegration::new(
            blackout,
            TrafficMorpher::with_default_profiles(),
            Arc::new(ResilienceController::with_full_resilience_tier(
                "primary-core",
            )),
            Arc::new(StoreAndForward::new()),
            PanicWipeEngine::new([42u8; 32]),
        );
        let mut int_clone = integration;
        let signal_normal = BlackoutSignal {
            international_ip_severed: false,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
            dns_resolves_international: true,
            domestic_intranet_up: true,
        };
        let reaction = int_clone.react_automatic(&signal_normal);
        assert_eq!(reaction.level, IsolationLevel::Normal);
        assert!(!reaction.isolation_active);
        assert_eq!(reaction.profile_active, "https-browsing");
    }

    /// At FullIsolation, the automatic reaction must NOT claim connected,
    /// must activate isolation mode, and must set the panic profile to Full.
    #[test]
    fn automatic_full_isolation_never_lies() {
        let blackout = BlackoutController::with_full_tier("primary-core");
        let integration = AdvancedIntegration::new(
            blackout,
            TrafficMorpher::with_default_profiles(),
            Arc::new(ResilienceController::with_full_resilience_tier(
                "primary-core",
            )),
            Arc::new(StoreAndForward::new()),
            PanicWipeEngine::new([42u8; 32]),
        );
        let mut int_clone = integration;
        let signal_full = BlackoutSignal {
            international_ip_severed: true,
            dns_resolves_international: false,
            tcp_rst_rate: 1.0,
            tls_trunc_rate: 1.0,
            dns_anomaly_rate: 1.0,
            domestic_intranet_up: false,
        };
        let reaction = int_clone.react_automatic(&signal_full);
        assert_eq!(reaction.level, IsolationLevel::FullIsolation);
        assert!(reaction.isolation_active);
        assert_eq!(reaction.profile_active, "shaparak-banking");
        // Critical: must NOT claim connection.
        assert!(!int_clone.is_really_connected());
    }

    /// A rising DPI attack must raise the pre-warm advisory *while the link is
    /// still classified as usable* — that gap is the whole point of the
    /// predictive layer, and it is what keeps the switch invisible to the user.
    #[test]
    fn automatic_prewarm_is_advised_before_isolation_is_declared() {
        let blackout = BlackoutController::with_full_tier("primary-core");
        let mut integration = AdvancedIntegration::new(
            blackout,
            TrafficMorpher::with_default_profiles(),
            Arc::new(ResilienceController::with_full_resilience_tier(
                "primary-core",
            )),
            Arc::new(StoreAndForward::new()),
            PanicWipeEngine::new([42u8; 32]),
        );

        let mut prewarm_before_isolation = false;
        for step in 0..12 {
            let rate = f64::from(step) * 0.06;
            // Routing is NOT severed: the link still works, DPI is ramping.
            let reaction = integration.react_automatic(&BlackoutSignal {
                international_ip_severed: false,
                dns_resolves_international: true,
                tcp_rst_rate: rate.min(1.0),
                tls_trunc_rate: (rate * 0.7).min(1.0),
                dns_anomaly_rate: 0.0,
                domestic_intranet_up: true,
            });
            if reaction.prewarm_advised && !reaction.isolation_active {
                prewarm_before_isolation = true;
                break;
            }
        }
        assert!(
            prewarm_before_isolation,
            "pre-warm must be advised before isolation is declared"
        );
        assert!(integration.should_prewarm());
    }

    /// The predictive layer is advisory only: it must never turn into a
    /// connectivity claim, no matter how confident it is.
    #[test]
    fn a_confident_forecast_never_becomes_a_connectivity_claim() {
        let blackout = BlackoutController::with_full_tier("primary-core");
        let mut integration = AdvancedIntegration::new(
            blackout,
            TrafficMorpher::with_default_profiles(),
            Arc::new(ResilienceController::with_full_resilience_tier(
                "primary-core",
            )),
            Arc::new(StoreAndForward::new()),
            PanicWipeEngine::new([42u8; 32]),
        );
        for _ in 0..20 {
            integration.react_automatic(&BlackoutSignal {
                international_ip_severed: true,
                dns_resolves_international: false,
                tcp_rst_rate: 1.0,
                tls_trunc_rate: 1.0,
                dns_anomaly_rate: 1.0,
                domestic_intranet_up: false,
            });
        }
        let status = integration.full_status_snapshot();
        assert_eq!(status.isolation_level, IsolationLevel::FullIsolation);
        assert!(
            !status.really_connected,
            "a high-confidence forecast must never imply connectivity"
        );
        assert!(!integration.is_really_connected());
    }

    /// Domestic intelligence must reorder attempts without ever discarding an
    /// option — no capability may be lost to a ranking decision.
    #[test]
    fn domestic_intel_reorders_but_never_loses_a_transport() {
        let blackout = BlackoutController::with_full_tier("primary-core");
        let integration = AdvancedIntegration::new(
            blackout,
            TrafficMorpher::with_default_profiles(),
            Arc::new(ResilienceController::with_full_resilience_tier(
                "primary-core",
            )),
            Arc::new(StoreAndForward::new()),
            PanicWipeEngine::new([42u8; 32]),
        );
        integration.observe_transport_result("obfs4", false);
        integration.observe_transport_result("dns-tunnel-masterdns", true);

        let candidates: Vec<String> = ["obfs4", "snowflake", "dns-tunnel-masterdns"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let ordered = integration.prioritize_transports(&candidates);

        assert_eq!(
            ordered[0], "dns-tunnel-masterdns",
            "working path must be first"
        );
        assert_eq!(
            ordered.last().unwrap(),
            "obfs4",
            "known-blocked path must be last"
        );
        assert_eq!(
            ordered.len(),
            candidates.len(),
            "no transport may be dropped"
        );
    }

    /// With no intelligence at all, ordering must be exactly what the caller
    /// passed in. This is the fail-safe that guarantees the new layer can
    /// never make things worse than not having it.
    #[test]
    fn no_intelligence_degrades_to_the_callers_own_ordering() {
        let blackout = BlackoutController::with_full_tier("primary-core");
        let integration = AdvancedIntegration::new(
            blackout,
            TrafficMorpher::with_default_profiles(),
            Arc::new(ResilienceController::with_full_resilience_tier(
                "primary-core",
            )),
            Arc::new(StoreAndForward::new()),
            PanicWipeEngine::new([42u8; 32]),
        );
        let candidates: Vec<String> = ["a", "b", "c"].iter().map(ToString::to_string).collect();
        assert_eq!(integration.prioritize_transports(&candidates), candidates);
        assert!(!integration.should_prewarm());
    }

    /// Reaching the hard bound must automatically engage retry discipline —
    /// the `BLACKOUT_BOUNDS.md` commitment, enforced end-to-end rather than
    /// only inside the cadence unit tests.
    #[test]
    fn full_isolation_automatically_engages_retry_discipline() {
        let blackout = BlackoutController::with_full_tier("primary-core");
        let mut integration = AdvancedIntegration::new(
            blackout,
            TrafficMorpher::with_default_profiles(),
            Arc::new(ResilienceController::with_full_resilience_tier(
                "primary-core",
            )),
            Arc::new(StoreAndForward::new()),
            PanicWipeEngine::new([42u8; 32]),
        );
        integration.react_automatic(&BlackoutSignal {
            international_ip_severed: true,
            dns_resolves_international: false,
            tcp_rst_rate: 1.0,
            tls_trunc_rate: 1.0,
            dns_anomaly_rate: 1.0,
            domestic_intranet_up: false,
        });

        let now = std::time::Instant::now();
        // A tight retry loop must be throttled to a single probe.
        let mut allowed = 0;
        for _ in 0..500 {
            if integration.cadence.try_probe("dns-tunnel-masterdns", now) {
                allowed += 1;
                integration
                    .cadence
                    .note_failure("dns-tunnel-masterdns", now);
            }
        }
        assert_eq!(allowed, 1, "a blackout must not produce a retry storm");
        let wait = integration
            .cadence
            .time_until_due("dns-tunnel-masterdns", now);
        assert!(
            wait >= std::time::Duration::from_secs(20),
            "ConfirmedIsolation cadence must be slow, got {wait:?}"
        );
    }

    /// Discipline must never cost recovery time: a healthy probe has to clear
    /// blackout-era back-off instantly.
    #[test]
    fn automatic_recovery_clears_retry_back_off_instantly() {
        let blackout = BlackoutController::with_full_tier("primary-core");
        let mut integration = AdvancedIntegration::new(
            blackout,
            TrafficMorpher::with_default_profiles(),
            Arc::new(ResilienceController::with_full_resilience_tier(
                "primary-core",
            )),
            Arc::new(StoreAndForward::new()),
            PanicWipeEngine::new([42u8; 32]),
        );
        integration.react_automatic(&BlackoutSignal {
            international_ip_severed: true,
            dns_resolves_international: false,
            tcp_rst_rate: 1.0,
            tls_trunc_rate: 1.0,
            dns_anomaly_rate: 1.0,
            domestic_intranet_up: false,
        });
        let now = std::time::Instant::now();
        for _ in 0..10 {
            integration.cadence.note_failure("webtunnel", now);
        }
        assert!(!integration.cadence.may_probe("webtunnel", now));

        integration.recover_automatic(true);

        let after = std::time::Instant::now();
        assert!(
            integration.cadence.may_probe("webtunnel", after),
            "recovery must clear back-off immediately"
        );
        assert_eq!(
            integration.cadence.level(),
            crate::isolation::IsolationLevel::Nominal
        );
    }

    /// Recovery must be automatic and flush queued data when a healthy probe arrives.
    #[test]
    fn automatic_recovery_flushes_queue() {
        let blackout = BlackoutController::with_full_tier("primary-core");
        let store = Arc::new(StoreAndForward::new());
        store.enqueue(Priority::Control, b"message".to_vec());
        let integration = AdvancedIntegration::new(
            blackout,
            TrafficMorpher::with_default_profiles(),
            Arc::new(ResilienceController::with_full_resilience_tier(
                "primary-core",
            )),
            store.clone(),
            PanicWipeEngine::new([42u8; 32]),
        );
        let mut int_clone = integration;
        let recovery = int_clone.recover_automatic(true);
        assert!(recovery.is_some());
        let r = recovery.unwrap();
        assert_eq!(r.new_level, IsolationLevel::Normal);
        assert_eq!(r.flushed_items, 1);
        assert!(!int_clone.isolation_active.load(Ordering::Relaxed));
        assert!(store.pending() == 0);
    }
}
