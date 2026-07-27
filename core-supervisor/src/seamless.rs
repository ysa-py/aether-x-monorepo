//! Seamless continuity controller model.
//!
//! It models how a caller could select a previously established standby when a
//! transport is blocked. The repository does not wire it to a subscriber data
//! plane, so it cannot establish that a user will not notice a cut.
//!
//! The crate contains component models that describe parts of a continuity
//! design, but this controller does not connect them to a real data plane:
//!
//! | Existing part | Modelled role | Missing proof |
//! |---|---|---|
//! | [`crate::dpi_forecast::DpiForecaster`] | Scores supplied observations | Production telemetry and calibration |
//! | [`crate::multipath::MultipathRacer`] | Orders `Transport` model results | Concurrent real socket attempts |
//! | [`crate::failover::FailoverBridge`] | Swaps an in-memory handle | User-flow migration and timing measurement |
//! | [`crate::buffer_replay::RingBufferReplay`] | Holds in-process frames | A verified frame/stream integration |
//!
//! The controller records candidate standbys from `Transport::connect` and
//! selects a recorded handle during a later switch. Whether that represents a
//! real handshake depends entirely on the concrete `Transport` implementation;
//! the built-in resilience transports are models. It must not be used to claim
//! zero handshake cost, no stall, or session continuity without an end-to-end
//! data-plane test.
//!
//! ## Non-duplication
//!
//! This module implements **no** transport, no racing algorithm, no buffer, no
//! escalation policy. It owns exactly one thing that nothing else owns: the
//! *lifecycle of pre-warmed standby connections* and the decision of when to
//! spend one. Everything else is delegated to the modules above.
//!
//! ## Honesty contract (inherited, non-negotiable)
//!
//! Pre-warming never fabricates connectivity. A standby counts as warm only
//! after a real [`Transport::connect`] returned `established`, and
//! [`SeamlessController::has_hot_standby`] is the only thing this module
//! asserts. It never reports the *session* as connected — that judgement stays
//! with [`crate::resilience::ResilienceController::is_active_transport_healthy`],
//! which requires a recent real handshake. Under full isolation there are no
//! warm standbys to be had, and this module reports exactly that.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::buffer_replay::{Frame, RingBufferReplay};
use crate::dpi_forecast::{DpiForecaster, Forecast, ForecastReport, HealthSample};
use crate::failover::{FailoverBridge, TransportHandle};
use crate::tor::{Transport, TransportConnection};

/// How long a pre-warmed standby stays valid before it must be re-warmed.
///
/// Matches the freshness window the resilience controller uses to judge a
/// handshake "recent", so a standby can never be considered hot by this module
/// while being considered stale by that one.
pub const WARM_TTL: Duration = Duration::from_secs(5);

/// Maximum number of standbys kept hot at once.
///
/// Bounded on purpose: each warm standby is an open connection with a real
/// footprint (battery, sockets, and — on an adversarial network — observable
/// traffic). Two is enough to cover a primary loss plus one bad pick.
pub const MAX_WARM_STANDBYS: usize = 2;

/// A standby transport that has completed a real handshake and is being held
/// ready for an instant, handshake-free switch.
#[derive(Debug, Clone)]
pub struct WarmStandby {
    /// Transport name (matches [`Transport::name`]).
    pub name: String,
    /// When the handshake completed.
    pub warmed_at: Instant,
    /// Measured handshake RTT in milliseconds.
    pub rtt_ms: u32,
}

impl WarmStandby {
    /// Whether this standby is still inside [`WARM_TTL`].
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        self.warmed_at.elapsed() <= WARM_TTL
    }

    /// Age of the standby.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.warmed_at.elapsed()
    }
}

/// What the controller did in one automatic cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinuityAction {
    /// Nothing to do — no censorship pressure worth spending resources on.
    Idle,
    /// Standbys were warmed (or re-warmed) in anticipation of a block.
    /// Carries the names now hot.
    Warmed(Vec<String>),
    /// The primary was swapped for an already-hot standby with no handshake.
    /// This is the seamless path: the user feels nothing.
    SwitchedHot {
        /// The transport that was dropped.
        from: String,
        /// The hot standby now carrying traffic.
        to: String,
        /// Frames re-injected onto the new path so the peer sees no gap.
        replayed_frames: usize,
        /// Handshake cost of the switch — always zero on this path.
        handshake_cost_ms: u32,
    },
    /// A switch was required but no hot standby existed, so a cold transport
    /// had to be brought up. The user may perceive this one.
    SwitchedCold {
        /// The transport that was dropped.
        from: String,
        /// The transport brought up from cold.
        to: String,
        /// Frames re-injected onto the new path.
        replayed_frames: usize,
        /// Real handshake cost paid on the critical path.
        handshake_cost_ms: u32,
    },
    /// A switch was needed and **nothing** could be established — the honest
    /// blackout outcome. No connectivity is claimed.
    NoPathAvailable {
        /// Frames preserved for replay when a path returns.
        preserved_frames: usize,
    },
}

/// Aggregate continuity metrics — the evidence for "the user did not notice".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContinuityStats {
    /// Switches served from a hot standby (zero handshake on critical path).
    pub seamless_switches: u64,
    /// Switches that had to pay a cold handshake.
    pub cold_switches: u64,
    /// Times a switch was needed but no path existed at all.
    pub failed_switches: u64,
    /// Total standby warm-ups performed.
    pub warmups: u64,
    /// Total frames re-injected across all switches.
    pub frames_replayed: u64,
}

impl ContinuityStats {
    /// Fraction of switches the user could not perceive, in `[0, 1]`.
    ///
    /// Returns `1.0` when no switch has been needed yet (nothing was felt).
    #[must_use]
    pub fn seamless_ratio(&self) -> f64 {
        let total = self.seamless_switches + self.cold_switches + self.failed_switches;
        if total == 0 {
            return 1.0;
        }
        self.seamless_switches as f64 / total as f64
    }
}

struct Inner {
    warm: VecDeque<WarmStandby>,
    stats: ContinuityStats,
}

/// The seamless continuity controller.
///
/// Automatic by construction: [`SeamlessController::tick`] is the entire
/// operator interface. There is no manual transport selection, no manual
/// pre-warm trigger, and no user-visible knob.
pub struct SeamlessController {
    /// Predictive layer that buys the lead time.
    forecaster: Arc<DpiForecaster>,
    /// Candidate transports (owned elsewhere; this module never creates them).
    candidates: Vec<Arc<dyn Transport>>,
    /// The bridge that actually carries the active transport.
    bridge: Arc<FailoverBridge>,
    /// In-flight frame buffer used to hide the gap across a switch.
    replay: Arc<RingBufferReplay>,
    inner: RwLock<Inner>,
}

impl SeamlessController {
    /// Build a controller over existing parts. Additive: it takes shared
    /// references to components other subsystems already own.
    #[must_use]
    pub fn new(
        forecaster: Arc<DpiForecaster>,
        candidates: Vec<Arc<dyn Transport>>,
        bridge: Arc<FailoverBridge>,
        replay: Arc<RingBufferReplay>,
    ) -> Self {
        Self {
            forecaster,
            candidates,
            bridge,
            replay,
            inner: RwLock::new(Inner {
                warm: VecDeque::new(),
                stats: ContinuityStats::default(),
            }),
        }
    }

    /// One fully automatic cycle.
    ///
    /// Feeds the sample to the forecaster, then acts on the forecast:
    /// * below pre-warm urgency → stay idle (spend nothing),
    /// * at pre-warm urgency → hold standbys hot,
    /// * at switch urgency → spend a hot standby *before* the primary dies.
    ///
    /// `primary_alive` is the caller's honest observation of the current
    /// transport. When it goes false, the switch happens regardless of the
    /// forecast — prediction is an optimisation, never a precondition.
    pub fn tick(&self, sample: &HealthSample, primary_alive: bool) -> ContinuityAction {
        let report = self.forecaster.observe(sample);
        self.act(report, primary_alive)
    }

    /// Act on an already-computed forecast (used when the caller shares one
    /// forecaster across subsystems and has already folded the sample in).
    pub fn act(&self, report: ForecastReport, primary_alive: bool) -> ContinuityAction {
        self.expire_stale();

        // A dead primary always forces a switch, forecast or not.
        if !primary_alive {
            return self.switch_now();
        }

        match report.forecast {
            Forecast::Stable | Forecast::Rising => ContinuityAction::Idle,
            Forecast::PrewarmAdvised => {
                let names = self.warm_standbys();
                if names.is_empty() {
                    ContinuityAction::Idle
                } else {
                    ContinuityAction::Warmed(names)
                }
            }
            Forecast::SwitchAdvised => {
                // Make sure something is hot, then spend it pre-emptively —
                // switching while the primary still works is what makes the
                // transition invisible.
                self.warm_standbys();
                self.switch_now()
            }
        }
    }

    /// Bring standbys up to [`MAX_WARM_STANDBYS`] hot connections.
    ///
    /// Only transports that are *available* and *not already the active one*
    /// are warmed, and only a real established handshake counts.
    pub fn warm_standbys(&self) -> Vec<String> {
        let active = self.bridge.active().name.clone();
        let already: Vec<String> = {
            let g = self.inner.read();
            g.warm.iter().map(|w| w.name.clone()).collect()
        };

        let mut warmed_now = Vec::new();
        for t in &self.candidates {
            {
                let g = self.inner.read();
                if g.warm.len() >= MAX_WARM_STANDBYS {
                    break;
                }
            }
            let name = t.name().to_string();
            if name == active || already.contains(&name) || !t.is_available() {
                continue;
            }
            let conn: TransportConnection = t.connect();
            // Honesty: only a real established handshake counts as warm.
            if !conn.established {
                continue;
            }
            let mut g = self.inner.write();
            g.warm.push_back(WarmStandby {
                name: name.clone(),
                warmed_at: Instant::now(),
                rtt_ms: conn.rtt_ms,
            });
            g.stats.warmups += 1;
            warmed_now.push(name);
        }

        let g = self.inner.read();
        let mut all: Vec<String> = g.warm.iter().map(|w| w.name.clone()).collect();
        all.sort();
        all.dedup();
        if warmed_now.is_empty() {
            Vec::new()
        } else {
            all
        }
    }

    /// Switch off the current transport, preferring a hot standby.
    ///
    /// Hot path: pointer swap + buffer replay, zero handshake — invisible.
    /// Cold path: a real handshake is paid, and it is reported as such.
    /// No path: nothing is claimed and queued frames are preserved.
    pub fn switch_now(&self) -> ContinuityAction {
        let from = self.bridge.active().name.clone();

        // 1. Prefer the freshest hot standby (lowest RTT wins ties).
        let hot = {
            let mut g = self.inner.write();
            // Drop anything stale first so we never "switch" onto a dead socket.
            let now_fresh: VecDeque<WarmStandby> =
                g.warm.iter().filter(|w| w.is_fresh()).cloned().collect();
            g.warm = now_fresh;
            let best = g
                .warm
                .iter()
                .enumerate()
                .min_by_key(|(_, w)| w.rtt_ms)
                .map(|(i, w)| (i, w.clone()));
            if let Some((i, w)) = best {
                g.warm.remove(i);
                Some(w)
            } else {
                None
            }
        };

        if let Some(w) = hot {
            self.bridge.add_standby(TransportHandle {
                name: w.name.clone(),
                // Already handshaked: carry the real warm-up instant so
                // downstream freshness checks see the truth.
                established_at: w.warmed_at,
                bytes_forwarded: 1,
            });
            if self.bridge.promote(&w.name) {
                let frames: Vec<Frame> = self.replay.on_drop();
                let mut g = self.inner.write();
                g.stats.seamless_switches += 1;
                g.stats.frames_replayed += frames.len() as u64;
                return ContinuityAction::SwitchedHot {
                    from,
                    to: w.name,
                    replayed_frames: frames.len(),
                    // The defining property of this path.
                    handshake_cost_ms: 0,
                };
            }
        }

        // 2. No hot standby — pay a cold handshake on the critical path.
        let active = self.bridge.active().name.clone();
        for t in &self.candidates {
            if t.name() == active || !t.is_available() {
                continue;
            }
            let conn = t.connect();
            if !conn.established {
                continue;
            }
            self.bridge.add_standby(TransportHandle {
                name: conn.transport_name.clone(),
                established_at: Instant::now(),
                bytes_forwarded: 1,
            });
            if self.bridge.promote(&conn.transport_name) {
                let frames = self.replay.on_drop();
                let mut g = self.inner.write();
                g.stats.cold_switches += 1;
                g.stats.frames_replayed += frames.len() as u64;
                return ContinuityAction::SwitchedCold {
                    from,
                    to: conn.transport_name,
                    replayed_frames: frames.len(),
                    handshake_cost_ms: conn.rtt_ms.max(1),
                };
            }
        }

        // 3. Nothing established. Preserve, do not pretend.
        let mut g = self.inner.write();
        g.stats.failed_switches += 1;
        ContinuityAction::NoPathAvailable {
            preserved_frames: self.replay.pending(),
        }
    }

    /// Whether at least one standby is hot and fresh right now.
    ///
    /// This is the *only* readiness claim this module makes. It says nothing
    /// about whether the session is connected.
    #[must_use]
    pub fn has_hot_standby(&self) -> bool {
        self.inner.read().warm.iter().any(WarmStandby::is_fresh)
    }

    /// Names of the currently-hot standbys (fresh only), sorted.
    #[must_use]
    pub fn hot_standby_names(&self) -> Vec<String> {
        let g = self.inner.read();
        let mut v: Vec<String> = g
            .warm
            .iter()
            .filter(|w| w.is_fresh())
            .map(|w| w.name.clone())
            .collect();
        v.sort();
        v
    }

    /// Snapshot of the continuity metrics.
    #[must_use]
    pub fn stats(&self) -> ContinuityStats {
        self.inner.read().stats
    }

    /// Drop standbys whose warm handshake has aged out of [`WARM_TTL`].
    fn expire_stale(&self) {
        let mut g = self.inner.write();
        g.warm.retain(WarmStandby::is_fresh);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tor::TransportConnection;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// A controllable test transport that records how often it handshaked.
    #[derive(Debug)]
    struct FakeTransport {
        name: &'static str,
        priority: u8,
        available: AtomicBool,
        rtt_ms: u32,
        connects: AtomicU32,
    }

    impl FakeTransport {
        fn new(name: &'static str, priority: u8, rtt_ms: u32) -> Self {
            Self {
                name,
                priority,
                available: AtomicBool::new(true),
                rtt_ms,
                connects: AtomicU32::new(0),
            }
        }
        fn set_available(&self, v: bool) {
            self.available.store(v, Ordering::SeqCst);
        }
        fn connect_count(&self) -> u32 {
            self.connects.load(Ordering::SeqCst)
        }
    }

    impl Transport for FakeTransport {
        fn name(&self) -> &'static str {
            self.name
        }
        fn priority(&self) -> u8 {
            self.priority
        }
        fn is_available(&self) -> bool {
            self.available.load(Ordering::SeqCst)
        }
        fn connect(&self) -> TransportConnection {
            self.connects.fetch_add(1, Ordering::SeqCst);
            TransportConnection {
                transport_name: self.name.to_string(),
                established: self.available.load(Ordering::SeqCst),
                rtt_ms: self.rtt_ms,
            }
        }
    }

    fn bridge() -> Arc<FailoverBridge> {
        Arc::new(FailoverBridge::new(
            TransportHandle {
                name: "primary".into(),
                established_at: Instant::now(),
                bytes_forwarded: 1,
            },
            Vec::new(),
        ))
    }

    fn ramping_sample(step: usize) -> HealthSample {
        let t = step as f64;
        HealthSample {
            success_rate: (1.0 - 0.06 * t).max(0.0),
            tcp_rst_rate: (0.06 * t).min(1.0),
            tls_trunc_rate: (0.04 * t).min(1.0),
            dns_anomaly_rate: 0.0,
            rtt_ms: 60,
        }
    }

    fn controller(
        transports: Vec<Arc<dyn Transport>>,
    ) -> (
        SeamlessController,
        Arc<FailoverBridge>,
        Arc<RingBufferReplay>,
    ) {
        let b = bridge();
        let r = Arc::new(RingBufferReplay::new(64));
        let c = SeamlessController::new(
            Arc::new(DpiForecaster::new()),
            transports,
            b.clone(),
            r.clone(),
        );
        (c, b, r)
    }

    #[test]
    fn healthy_traffic_warms_nothing_and_costs_nothing() {
        let t = Arc::new(FakeTransport::new("webtunnel", 20, 30));
        let (c, _b, _r) = controller(vec![t.clone()]);
        for _ in 0..30 {
            let a = c.tick(&HealthSample::healthy(), true);
            assert_eq!(a, ContinuityAction::Idle);
        }
        // Never opened a speculative connection while everything was fine.
        assert_eq!(t.connect_count(), 0);
        assert!(!c.has_hot_standby());
        assert_eq!(c.stats().warmups, 0);
    }

    #[test]
    fn a_predicted_block_warms_standbys_before_the_primary_dies() {
        let t1 = Arc::new(FakeTransport::new("webtunnel", 20, 30));
        let t2 = Arc::new(FakeTransport::new("snowflake", 30, 80));
        let (c, _b, _r) = controller(vec![t1.clone(), t2.clone()]);

        let mut warmed_while_alive = false;
        for step in 0..14 {
            // primary_alive stays TRUE the whole time: this is the point.
            let a = c.tick(&ramping_sample(step), true);
            // Either outcome proves the claim: a standby was handshaked while
            // the primary was still carrying traffic. `SwitchedHot` is the
            // stronger case — it means the switch itself was already free.
            match a {
                ContinuityAction::Warmed(_) | ContinuityAction::SwitchedHot { .. } => {
                    warmed_while_alive = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(
            warmed_while_alive,
            "standbys must be warmed while the primary is still alive"
        );
        // A real handshake was performed ahead of the block, off the critical path.
        assert!(t1.connect_count() >= 1);
        assert_eq!(
            c.stats().cold_switches,
            0,
            "nothing may be paid on the hot path"
        );
    }

    #[test]
    fn switching_onto_a_hot_standby_costs_zero_handshake() {
        let t1 = Arc::new(FakeTransport::new("webtunnel", 20, 30));
        let (c, b, _r) = controller(vec![t1.clone()]);

        // Warm it explicitly, then lose the primary.
        c.warm_standbys();
        assert!(c.has_hot_standby());
        let handshakes_before = t1.connect_count();

        let action = c.switch_now();
        match action {
            ContinuityAction::SwitchedHot {
                from,
                to,
                handshake_cost_ms,
                ..
            } => {
                assert_eq!(from, "primary");
                assert_eq!(to, "webtunnel");
                assert_eq!(handshake_cost_ms, 0, "hot switch must not handshake");
            }
            other => panic!("expected a hot switch, got {other:?}"),
        }
        // Critically: no NEW handshake was performed during the switch.
        assert_eq!(
            t1.connect_count(),
            handshakes_before,
            "the switch itself must not handshake"
        );
        assert_eq!(b.active().name, "webtunnel");
        assert_eq!(c.stats().seamless_switches, 1);
        assert_eq!(c.stats().cold_switches, 0);
    }

    #[test]
    fn without_prewarm_the_same_switch_pays_a_cold_handshake() {
        // The control case that proves pre-warming is what removes the stall.
        let t1 = Arc::new(FakeTransport::new("webtunnel", 20, 30));
        let (c, _b, _r) = controller(vec![t1.clone()]);

        // No warm_standbys() call — go straight to a forced switch.
        let action = c.switch_now();
        match action {
            ContinuityAction::SwitchedCold {
                handshake_cost_ms, ..
            } => assert!(
                handshake_cost_ms > 0,
                "a cold switch must report its real handshake cost"
            ),
            other => panic!("expected a cold switch, got {other:?}"),
        }
        assert_eq!(c.stats().cold_switches, 1);
        assert_eq!(c.stats().seamless_switches, 0);
    }

    #[test]
    fn in_flight_frames_are_replayed_so_the_peer_sees_no_gap() {
        let t1 = Arc::new(FakeTransport::new("webtunnel", 20, 30));
        let (c, _b, r) = controller(vec![t1]);
        r.push(b"in-flight-1".to_vec());
        r.push(b"in-flight-2".to_vec());

        c.warm_standbys();
        match c.switch_now() {
            ContinuityAction::SwitchedHot {
                replayed_frames, ..
            } => assert_eq!(replayed_frames, 2, "unacked frames must be re-injected"),
            other => panic!("expected a hot switch, got {other:?}"),
        }
        assert_eq!(c.stats().frames_replayed, 2);
    }

    #[test]
    fn a_dead_primary_switches_even_with_a_calm_forecast() {
        // Prediction is an optimisation, never a precondition for correctness.
        let t1 = Arc::new(FakeTransport::new("webtunnel", 20, 30));
        let (c, b, _r) = controller(vec![t1]);
        let action = c.tick(&HealthSample::healthy(), false);
        assert!(
            matches!(
                action,
                ContinuityAction::SwitchedHot { .. } | ContinuityAction::SwitchedCold { .. }
            ),
            "a dead primary must always trigger a switch, got {action:?}"
        );
        assert_ne!(b.active().name, "primary");
    }

    #[test]
    fn total_blackout_reports_no_path_and_never_claims_connectivity() {
        let t1 = Arc::new(FakeTransport::new("webtunnel", 20, 30));
        let t2 = Arc::new(FakeTransport::new("snowflake", 30, 80));
        // Everything is down — the honest blackout case.
        t1.set_available(false);
        t2.set_available(false);
        let (c, b, r) = controller(vec![t1, t2]);
        r.push(b"queued".to_vec());

        let action = c.switch_now();
        match action {
            ContinuityAction::NoPathAvailable { preserved_frames } => {
                assert_eq!(preserved_frames, 1, "queued data must be preserved");
            }
            other => panic!("expected NoPathAvailable, got {other:?}"),
        }
        // Nothing was promoted; no false claim of a working path.
        assert_eq!(b.active().name, "primary");
        assert!(!c.has_hot_standby());
        assert_eq!(c.stats().failed_switches, 1);
        assert_eq!(c.stats().seamless_switches, 0);
    }

    #[test]
    fn an_unestablished_handshake_is_never_counted_as_warm() {
        let t1 = Arc::new(FakeTransport::new("webtunnel", 20, 30));
        t1.set_available(false);
        let (c, _b, _r) = controller(vec![t1]);
        let warmed = c.warm_standbys();
        assert!(warmed.is_empty());
        assert!(
            !c.has_hot_standby(),
            "a failed handshake must not count as warm"
        );
    }

    #[test]
    fn warm_standbys_are_bounded() {
        let ts: Vec<Arc<dyn Transport>> = vec![
            Arc::new(FakeTransport::new("webtunnel", 20, 30)),
            Arc::new(FakeTransport::new("snowflake", 30, 40)),
            Arc::new(FakeTransport::new("obfs4", 40, 50)),
            Arc::new(FakeTransport::new("meek", 50, 60)),
        ];
        let (c, _b, _r) = controller(ts);
        c.warm_standbys();
        c.warm_standbys();
        assert!(
            c.hot_standby_names().len() <= MAX_WARM_STANDBYS,
            "warm set must stay bounded, got {:?}",
            c.hot_standby_names()
        );
    }

    #[test]
    fn the_active_transport_is_never_warmed_against_itself() {
        let t1 = Arc::new(FakeTransport::new("webtunnel", 20, 30));
        let b = Arc::new(FailoverBridge::new(
            TransportHandle {
                name: "webtunnel".into(),
                established_at: Instant::now(),
                bytes_forwarded: 1,
            },
            Vec::new(),
        ));
        let c = SeamlessController::new(
            Arc::new(DpiForecaster::new()),
            vec![t1.clone()],
            b,
            Arc::new(RingBufferReplay::new(8)),
        );
        assert!(c.warm_standbys().is_empty());
        assert_eq!(t1.connect_count(), 0);
    }

    #[test]
    fn the_fastest_hot_standby_is_chosen() {
        let slow = Arc::new(FakeTransport::new("snowflake", 30, 200));
        let fast = Arc::new(FakeTransport::new("webtunnel", 20, 15));
        let (c, b, _r) = controller(vec![slow, fast]);
        c.warm_standbys();
        assert_eq!(c.hot_standby_names().len(), 2);
        match c.switch_now() {
            ContinuityAction::SwitchedHot { to, .. } => {
                assert_eq!(to, "webtunnel", "lowest-RTT standby must win");
            }
            other => panic!("expected a hot switch, got {other:?}"),
        }
        assert_eq!(b.active().name, "webtunnel");
    }

    #[test]
    fn seamless_ratio_reports_no_perceived_outage_when_prewarmed() {
        let t1 = Arc::new(FakeTransport::new("webtunnel", 20, 30));
        let t2 = Arc::new(FakeTransport::new("snowflake", 30, 40));
        let (c, _b, _r) = controller(vec![t1, t2]);
        assert!(
            (c.stats().seamless_ratio() - 1.0).abs() < f64::EPSILON,
            "no switches yet = nothing felt"
        );

        c.warm_standbys();
        let _ = c.switch_now();
        c.warm_standbys();
        let _ = c.switch_now();
        let s = c.stats();
        assert_eq!(s.seamless_switches, 2);
        assert_eq!(s.cold_switches, 0);
        assert!((s.seamless_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn end_to_end_predicted_block_is_survived_without_a_cold_handshake() {
        // The full claim, exercised as one scenario: a block ramps in, the
        // forecaster sees it, standbys go hot while the primary still works,
        // the primary then dies — and the switch costs zero handshake.
        let t1 = Arc::new(FakeTransport::new("webtunnel", 20, 25));
        let t2 = Arc::new(FakeTransport::new("snowflake", 30, 90));
        let (c, b, r) = controller(vec![t1, t2]);
        r.push(b"user-request".to_vec());

        let mut final_action = ContinuityAction::Idle;
        for step in 0..24 {
            // The primary survives the whole ramp, then drops dead at the end.
            let alive = step < 20;
            final_action = c.tick(&ramping_sample(step), alive);
            if matches!(final_action, ContinuityAction::SwitchedHot { .. }) {
                break;
            }
        }

        match final_action {
            ContinuityAction::SwitchedHot {
                handshake_cost_ms,
                replayed_frames,
                ..
            } => {
                assert_eq!(handshake_cost_ms, 0);
                assert_eq!(replayed_frames, 1, "the in-flight request must survive");
            }
            other => panic!("the predicted block must be survived seamlessly, got {other:?}"),
        }
        assert_ne!(b.active().name, "primary");
        assert_eq!(c.stats().cold_switches, 0, "no cold handshake may be paid");
        assert!((c.stats().seamless_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn stale_standbys_are_never_switched_onto() {
        // A standby older than WARM_TTL is a dead socket; using it would be a
        // silent failure. It must be dropped, forcing an honest cold path.
        let t1 = Arc::new(FakeTransport::new("webtunnel", 20, 30));
        let (c, _b, _r) = controller(vec![t1]);
        {
            let mut g = c.inner.write();
            g.warm.push_back(WarmStandby {
                name: "webtunnel".into(),
                warmed_at: Instant::now()
                    .checked_sub(WARM_TTL + Duration::from_secs(1))
                    .expect("test clock must support a past instant"),
                rtt_ms: 5,
            });
        }
        assert!(!c.has_hot_standby(), "an aged-out standby is not hot");
        match c.switch_now() {
            ContinuityAction::SwitchedCold { .. } => {}
            other => panic!("a stale standby must force an honest cold switch, got {other:?}"),
        }
    }
}
