//! Blackout Isolation Bounds — operational model + automatic controller.
//!
//! This is the honest answer to the hardest question: *"when international
//! internet access is cut, what still works — and where is the limit no
//! software can cross?"*
//!
//! If a censor severs international IP routing while DNS still resolves
//! internationally, an independently deployed and verified tunnel might have a
//! remaining path. This module only models that conditional decision; it does
//! not establish such a tunnel. If international DNS resolution is also severed,
//! there is nothing for software-only transport to ride. That is the **hard
//! bound**: no software defeats a fully severed international reachability
//! layer. Past it, only a separately deployed domestically reachable bridge can
//! serve domestic content; it is not open-Internet connectivity.
//!
//! What this module actually delivers (and does not over-promise):
//!   - **Classify** a caller-supplied signal snapshot deterministically.
//!   - **Select** a profile name and a model transport ordering as isolation
//!     deepens; it does not collect probes or mutate live packets itself.
//!   - **Model** escalation through the in-process resilience registry. The
//!     registry must be backed by real, independently probed transports before
//!     this can be treated as an operational failover path.
//!   - **Report the bound honestly** when even DNS resolution is gone, instead
//!     of pretending a connection exists that cannot exist.
//!
//! The supervisor executable does not construct this controller today. See the
//! repository continuity audit for the runtime-wiring and integration-test gap.

use crate::ai_dpi::TrafficMorpher;
use crate::multipath::{MultipathBond, MultipathRacer};
use crate::policy::Decision;
use crate::resilience::{EscalationOutcome, ResilienceController};
use std::time::Duration;

/// Classified severity of network isolation, ordered least→most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// Normal operation; primary TLS cores (Reality/Vision, Hysteria2…) carry traffic.
    Normal,
    /// Active DPI (RST injection / TLS truncation / DNS tampering) is firing, but
    /// international IP routing still works — anti-DPI morphing + protocol hot-swap.
    DpiBlocking,
    /// International IP routing is severed, but DNS still resolves internationally —
    /// the Tor pluggable transports and DNS tunnels can still ride a path to the
    /// open internet.
    RoutingSevered,
    /// Full international isolation: even international DNS resolution is severed.
    /// **THE HARD BOUND** — no international transport works; only a domestic
    /// intranet bridge (domestic content) can stay reachable.
    FullIsolation,
}

impl IsolationLevel {
    /// Numeric severity (0=Normal … 3=FullIsolation) for ordering.
    #[must_use]
    pub fn severity(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::DpiBlocking => 1,
            Self::RoutingSevered => 2,
            Self::FullIsolation => 3,
        }
    }

    /// Whether this level has hit the hard international-isolation bound.
    #[must_use]
    pub fn is_hard_bound(self) -> bool {
        matches!(self, Self::FullIsolation)
    }
}

/// Raw signals the controller classifies from. Rates are windowed 0.0–1.0
/// (see [`crate::policy::FailureSignature`]); the three booleans are active
/// probe results.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct BlackoutSignal {
    /// Windowed rate of locally observed TCP `ConnectionReset` errors. This is
    /// a reset candidate, not proof that an on-path censor injected an RST.
    pub tcp_rst_rate: f64,
    /// Windowed rate of TLS handshakes interrupted after ClientHello
    /// transmission by EOF or reset; the source does not attribute who closed
    /// the flow.
    pub tls_trunc_rate: f64,
    /// Windowed rate of pinned DNS-anchor responses that disagree with their
    /// expected answer/response code.
    pub dns_anomaly_rate: f64,
    /// Conservative windowed indication that every configured international TCP
    /// anchor failed; it is not a claim of nationwide route visibility.
    pub international_ip_severed: bool,
    /// Whether at least one pinned direct DNS anchor returned an expected answer
    /// in the current window.
    pub dns_resolves_international: bool,
    /// Whether an operator-designated domestic TCP anchor accepted a connection
    /// in the current window.
    pub domestic_intranet_up: bool,
}

/// A signal rate at/above which an attack is considered "active".
const ACTIVE_RATE: f64 = 0.5;

/// Classify an isolation level from a signal snapshot. Pure + deterministic.
#[must_use]
pub fn classify(s: &BlackoutSignal) -> IsolationLevel {
    if s.international_ip_severed {
        // Routing to international IPs is gone. The deciding factor is whether
        // international DNS resolution still rides a path the DNS tunnel can use.
        return if s.dns_resolves_international {
            IsolationLevel::RoutingSevered
        } else {
            IsolationLevel::FullIsolation
        };
    }
    // International routing is up — the only question is active DPI.
    let dpi_active = s.tcp_rst_rate >= ACTIVE_RATE
        || s.tls_trunc_rate >= ACTIVE_RATE
        || s.dns_anomaly_rate >= ACTIVE_RATE;
    if dpi_active {
        IsolationLevel::DpiBlocking
    } else {
        IsolationLevel::Normal
    }
}

/// International paths that can still reach the open internet at this level.
/// Empty at [`IsolationLevel::FullIsolation`] — that is the bound.
#[must_use]
pub fn international_surviving_paths(level: IsolationLevel) -> &'static [&'static str] {
    match level {
        IsolationLevel::Normal => &["primary-tls-core"],
        IsolationLevel::DpiBlocking => {
            &["ai-traffic-morph", "protocol-hot-swap", "primary-tls-core"]
        }
        IsolationLevel::RoutingSevered => &[
            "tor-pluggable-transports",
            "dns-tunnel-masterdns",
            "dns-tunnel-vaydns-doh",
        ],
        IsolationLevel::FullIsolation => &[],
    }
}

/// The built-in traffic-shaping profile selected by this model at each level.
/// The profile names/values are static source data, not measured whitelist
/// evidence for a particular network.
#[must_use]
pub fn recommended_morph_profile(level: IsolationLevel) -> &'static str {
    match level {
        IsolationLevel::Normal => "https-browsing",
        IsolationLevel::DpiBlocking => "aparat-vod",
        // This is a deterministic profile-selection policy only. It is not
        // evidence that the named traffic survives a given network condition.
        IsolationLevel::RoutingSevered | IsolationLevel::FullIsolation => "shaparak-banking",
    }
}

/// The result of one controller reaction cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlackoutAction {
    /// Newly-classified isolation level.
    pub level: IsolationLevel,
    /// Transport promoted onto the failover bridge this cycle (if any).
    pub promoted_transport: Option<String>,
    /// Traffic-morph profile now active.
    pub morph_profile: String,
    /// True when the hard international-isolation bound is reached.
    pub bound_reached: bool,
    /// International paths still alive at this level (empty at the bound).
    pub surviving_paths: &'static [&'static str],
    /// Whether a domestic intranet bridge is reachable (domestic-only fallback).
    pub domestic_bridge_available: bool,
}

/// Owns the AI morpher + resilience tier and reacts to blackout signals in one
/// call. This is the single automatic decision point: detect → morph →
/// escalate (or flag the bound).
pub struct BlackoutController {
    morpher: TrafficMorpher,
    resilience: ResilienceController,
    level: IsolationLevel,
}

impl BlackoutController {
    /// Construct from explicit parts (tests build custom registries this way).
    #[must_use]
    pub fn new(morpher: TrafficMorpher, resilience: ResilienceController) -> Self {
        Self {
            morpher,
            resilience,
            level: IsolationLevel::Normal,
        }
    }

    /// Build a controller with the full last-resort tier (all PTs + both DNS
    /// tunnels) and the default three-profile Iranian morpher.
    #[must_use]
    pub fn with_full_tier(primary_name: &str) -> Self {
        Self::new(
            TrafficMorpher::with_default_profiles(),
            ResilienceController::with_full_resilience_tier(primary_name),
        )
    }

    /// React to a fresh signal snapshot. Drives morphing + escalation and
    /// returns exactly what happened (for status UI / metrics).
    pub fn react(&mut self, signal: &BlackoutSignal) -> BlackoutAction {
        let new_level = classify(signal);

        // 1. Adopt the most-survivable domestic morph profile for this level.
        let morph = recommended_morph_profile(new_level);
        self.morpher.select_profile(morph);

        // 2. Escalate to the last-resort tier ONLY at RoutingSevered — that is the
        //    one level where a DNS tunnel can still ride surviving international
        //    DNS resolution to reach the open internet. At FullIsolation even
        //    that resolution is gone, so escalating is futile: nothing
        //    international can connect (the hard bound).
        let promoted = if new_level == IsolationLevel::RoutingSevered {
            match self.resilience.apply_decision(&Decision::Escalate) {
                EscalationOutcome::EscalatedTo(name) => Some(name),
                _ => None,
            }
        } else {
            None
        };

        self.level = new_level;
        BlackoutAction {
            level: new_level,
            promoted_transport: promoted,
            morph_profile: morph.to_string(),
            bound_reached: new_level.is_hard_bound(),
            surviving_paths: international_surviving_paths(new_level),
            domestic_bridge_available: signal.domestic_intranet_up,
        }
    }

    /// React with the **strongest** strategy: detect → morph → escalate (base
    /// [`BlackoutController::react`]), and when the last-resort tier is engaged
    /// also RACE every transport concurrently (fastest establish wins, so the
    /// user never waits through a serial fallback chain) and BOND the survivors
    /// for aggregated throughput. Returns the augmented [`FastBlackoutAction`].
    pub fn react_fast(&mut self, signal: &BlackoutSignal) -> FastBlackoutAction {
        let base = self.react(signal);
        if base.level != IsolationLevel::RoutingSevered {
            return FastBlackoutAction {
                base,
                race_winner: None,
                bonded_paths: Vec::new(),
                throughput_multiplier: 1.0,
            };
        }
        let tier = self.resilience.registry().snapshot();
        let race = MultipathRacer::race(&tier, Duration::from_millis(500));
        let bond = MultipathBond::from_available(&tier);
        FastBlackoutAction {
            race_winner: race.winner.map(|c| c.transport_name),
            bonded_paths: bond.member_names(),
            throughput_multiplier: bond.aggregate_multiplier(),
            base,
        }
    }

    /// Current (last classified) isolation level.
    #[must_use]
    pub fn current_level(&self) -> IsolationLevel {
        self.level
    }

    /// Active morph profile name.
    #[must_use]
    pub fn active_morph_profile(&self) -> String {
        self.morpher.active_profile()
    }

    /// Borrow the resilience tier (introspection).
    #[must_use]
    pub fn resilience(&self) -> &ResilienceController {
        &self.resilience
    }
}

/// Augmented action: the base [`BlackoutAction`] plus the multipath race/bond
/// results when the tier is engaged. This is the "strongest, fastest, no
/// perceived-disconnect" path — race every transport, bond the survivors.
#[derive(Debug, Clone, PartialEq)]
pub struct FastBlackoutAction {
    /// The base detect→morph→escalate result.
    pub base: BlackoutAction,
    /// Fastest transport that established in the concurrent race (if any).
    pub race_winner: Option<String>,
    /// All bonded (available) transports carrying traffic in parallel.
    pub bonded_paths: Vec<String>,
    /// Aggregate-throughput multiplier from bonding (>1.0 when multiple paths).
    pub throughput_multiplier: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_tunnel::{DnsTunnelTransport, DnsTunnelVariant};
    use crate::failover::{FailoverBridge, TransportHandle};
    use crate::tor::TransportRegistry;
    use std::sync::Arc;
    use std::time::Instant;

    fn configured_dns_lifecycle_controller() -> BlackoutController {
        // Registry with a lifecycle-marked DNS tunnel but no real configured
        // connection endpoint. The controller must not promote it solely from
        // an in-memory health flag.
        let reg = TransportRegistry::new();
        let tunnel = Arc::new(DnsTunnelTransport::spawn(
            DnsTunnelVariant::MasterDnsVpn,
            "127.0.0.1:18000",
        ));
        tunnel.mark_healthy(true);
        reg.register(tunnel);
        let bridge = FailoverBridge::new(
            TransportHandle {
                name: "primary".into(),
                established_at: Instant::now(),
                bytes_forwarded: 0,
            },
            Vec::new(),
        );
        BlackoutController::new(
            TrafficMorpher::with_default_profiles(),
            ResilienceController::new(reg, bridge),
        )
    }

    #[test]
    fn classify_all_levels() {
        let normal = BlackoutSignal {
            international_ip_severed: false,
            tcp_rst_rate: 0.1,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.05,
            dns_resolves_international: true,
            domestic_intranet_up: true,
        };
        assert_eq!(classify(&normal), IsolationLevel::Normal);

        let dpi = BlackoutSignal {
            tcp_rst_rate: 0.8,
            ..normal
        };
        assert_eq!(classify(&dpi), IsolationLevel::DpiBlocking);

        let routing = BlackoutSignal {
            international_ip_severed: true,
            dns_resolves_international: true,
            ..normal
        };
        assert_eq!(classify(&routing), IsolationLevel::RoutingSevered);

        let full = BlackoutSignal {
            international_ip_severed: true,
            dns_resolves_international: false,
            ..normal
        };
        assert_eq!(classify(&full), IsolationLevel::FullIsolation);
    }

    #[test]
    fn severity_orders_and_bounds() {
        assert!(IsolationLevel::Normal.severity() < IsolationLevel::DpiBlocking.severity());
        assert!(IsolationLevel::DpiBlocking.severity() < IsolationLevel::RoutingSevered.severity());
        assert!(
            IsolationLevel::RoutingSevered.severity() < IsolationLevel::FullIsolation.severity()
        );
        assert!(IsolationLevel::FullIsolation.is_hard_bound());
        assert!(!IsolationLevel::RoutingSevered.is_hard_bound());
    }

    #[test]
    fn international_paths_empty_at_bound() {
        assert!(!international_surviving_paths(IsolationLevel::RoutingSevered).is_empty());
        assert!(international_surviving_paths(IsolationLevel::FullIsolation).is_empty());
    }

    #[test]
    fn morph_profile_deepens_with_isolation() {
        assert_eq!(
            recommended_morph_profile(IsolationLevel::Normal),
            "https-browsing"
        );
        assert_eq!(
            recommended_morph_profile(IsolationLevel::DpiBlocking),
            "aparat-vod"
        );
        assert_eq!(
            recommended_morph_profile(IsolationLevel::RoutingSevered),
            "shaparak-banking"
        );
    }

    #[test]
    fn controller_normal_no_escalation_https_morph() {
        let mut c = configured_dns_lifecycle_controller();
        let a = c.react(&BlackoutSignal {
            international_ip_severed: false,
            tcp_rst_rate: 0.1,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.05,
            dns_resolves_international: true,
            domestic_intranet_up: true,
        });
        assert_eq!(a.level, IsolationLevel::Normal);
        assert!(a.promoted_transport.is_none());
        assert_eq!(a.morph_profile, "https-browsing");
        assert!(!a.bound_reached);
    }

    #[test]
    fn controller_routing_severed_refuses_unconnected_dns_tunnel_and_morphs_banking() {
        let mut c = configured_dns_lifecycle_controller();
        let a = c.react(&BlackoutSignal {
            international_ip_severed: true,
            dns_resolves_international: true,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
            domestic_intranet_up: true,
        });
        assert_eq!(a.level, IsolationLevel::RoutingSevered);
        assert!(a.promoted_transport.is_none());
        assert_eq!(a.morph_profile, "shaparak-banking");
        assert!(!a.bound_reached);
        assert_eq!(c.resilience().bridge().active().name, "primary");
    }

    #[test]
    fn controller_full_isolation_reports_the_bound() {
        let mut c = configured_dns_lifecycle_controller();
        let a = c.react(&BlackoutSignal {
            international_ip_severed: true,
            dns_resolves_international: false,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
            domestic_intranet_up: true,
        });
        assert_eq!(a.level, IsolationLevel::FullIsolation);
        assert!(a.bound_reached);
        // Nothing international is promotable at the bound.
        assert!(a.promoted_transport.is_none());
        assert!(a.surviving_paths.is_empty());
        // …but a domestic intranet bridge stays reachable (domestic content only).
        assert!(a.domestic_bridge_available);
    }

    #[test]
    fn controller_escalates_through_levels_progressively() {
        let mut c = BlackoutController::with_full_tier("primary-core");
        // Normal.
        let a0 = c.react(&BlackoutSignal {
            international_ip_severed: false,
            dns_resolves_international: true,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
            domestic_intranet_up: true,
        });
        assert_eq!(a0.level, IsolationLevel::Normal);
        // DPI kicks in.
        let a1 = c.react(&BlackoutSignal {
            tcp_rst_rate: 0.9,
            ..a0_signal()
        });
        assert_eq!(a1.level, IsolationLevel::DpiBlocking);
        assert_eq!(a1.morph_profile, "aparat-vod");
        // Routing severed, DNS still resolves → escalate to the tier.
        let a2 = c.react(&BlackoutSignal {
            international_ip_severed: true,
            dns_resolves_international: true,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
            domestic_intranet_up: true,
        });
        assert_eq!(a2.level, IsolationLevel::RoutingSevered);
        // The default tier has no configured real endpoint, so classification
        // must not promote a conceptual transport merely from static eligibility.
        assert!(a2.promoted_transport.is_none());
    }

    #[test]
    fn react_fast_does_not_fabricate_unconfigured_connections() {
        // The full tier registers conceptual transports, but none has an
        // operator-configured endpoint in this test. A race must report no
        // winner/bond instead of assigning a static RTT or fake throughput.
        let mut c = BlackoutController::with_full_tier("primary-core");
        let action = c.react_fast(&BlackoutSignal {
            international_ip_severed: true,
            dns_resolves_international: true,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
            domestic_intranet_up: true,
        });
        assert_eq!(action.base.level, IsolationLevel::RoutingSevered);
        assert!(action.race_winner.is_none());
        assert!(action.bonded_paths.is_empty());
        assert!(
            action.throughput_multiplier.abs() < f64::EPSILON,
            "no measured connections means no claimed throughput"
        );
    }

    #[test]
    fn react_fast_is_a_no_op_below_routing_severed() {
        let mut c = BlackoutController::with_full_tier("primary-core");
        let action = c.react_fast(&BlackoutSignal {
            international_ip_severed: false,
            dns_resolves_international: true,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
            domestic_intranet_up: true,
        });
        assert_eq!(action.base.level, IsolationLevel::Normal);
        assert!(action.race_winner.is_none());
        assert!(action.bonded_paths.is_empty());
        assert!((action.throughput_multiplier - 1.0).abs() < f64::EPSILON);
    }

    // helper: a baseline signal mirroring the Normal react above (avoids repeating)
    fn a0_signal() -> BlackoutSignal {
        BlackoutSignal {
            international_ip_severed: false,
            dns_resolves_international: true,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
            domestic_intranet_up: true,
        }
    }
}
