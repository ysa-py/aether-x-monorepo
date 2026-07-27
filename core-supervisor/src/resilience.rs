//! Resilience controller — the cross-module wiring spec §4 flags as missing.
//!
//! [`crate::supervisor::CoreSupervisor`] only ever touches [`crate::protocol`]
//! adapters. The decider's [`crate::policy::Decision::Escalate`] (which fires
//! specifically on a high `dns_anomaly_rate` — precisely the signal a censor
//! tightening DNS-level blocking produces), [`crate::tor::TransportRegistry`],
//! and [`crate::failover::FailoverBridge`] all exist and are each tested in
//! isolation, but **nothing connected them end to end.**
//!
//! This module connects those in-process models: given a
//! [`crate::policy::Decision`] it selects an available registry entry and
//! promotes its name on the failover bridge. It does not open or forward a
//! last-resort transport; real failover semantics require a data-plane
//! integration and measurement.

use crate::dns_tunnel::{DnsTunnelTransport, DnsTunnelVariant};
use crate::failover::{FailoverBridge, TransportHandle};
use crate::policy::Decision;
use crate::ssh_tunnel::SshTunnelTransport;
use crate::tor::TransportRegistry;
use std::sync::Arc;
use std::time::Instant;

/// Outcome of applying a decider [`Decision`] to the resilience tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationOutcome {
    /// Decision was `Keep`/`Switch` — handled by the primary supervisor /
    /// hot-swap path; the last-resort tier stays dormant.
    NoAction,
    /// `Escalate`: a last-resort transport was selected and promoted onto the
    /// failover bridge (carries the promoted transport's name).
    EscalatedTo(String),
    /// `Escalate` was requested but no last-resort transport is currently
    /// available (e.g. the DNS-tunnel probe has not yet succeeded and all PTs
    /// are down). The bridge is left untouched.
    NoLastResortAvailable,
}

/// Owns the last-resort [`TransportRegistry`] + [`FailoverBridge`] and applies
/// decider decisions. This is the single place the escalation chain is wired.
pub struct ResilienceController {
    registry: TransportRegistry,
    bridge: FailoverBridge,
}

impl ResilienceController {
    /// Construct from an explicit registry + bridge.
    #[must_use]
    pub fn new(registry: TransportRegistry, bridge: FailoverBridge) -> Self {
        Self { registry, bridge }
    }

    /// Build a controller with the full last-resort tier: all Tor pluggable
    /// transports + Arti from [`TransportRegistry::with_all_transports`], plus
    /// both DNS tunnels (`MasterDnsVPN` + `VayDns`) registered dead-last at
    /// priority 100. `primary_name` seeds the bridge's active transport; the
    /// tier transports are promoted onto it dynamically on escalation (after a
    /// successful health probe flips them available).
    #[must_use]
    pub fn with_full_resilience_tier(primary_name: &str) -> Self {
        let registry = TransportRegistry::with_all_transports();
        registry.register(Arc::new(DnsTunnelTransport::spawn(
            DnsTunnelVariant::MasterDnsVpn,
            "127.0.0.1:18000",
        )));
        registry.register(Arc::new(DnsTunnelTransport::spawn(
            DnsTunnelVariant::VayDns,
            "127.0.0.1:18001",
        )));
        registry.register(Arc::new(DnsTunnelTransport::spawn(
            DnsTunnelVariant::NoizDns,
            "127.0.0.1:18002",
        )));
        registry.register(Arc::new(SshTunnelTransport::new("127.0.0.1:18003")));
        let bridge = FailoverBridge::new(
            TransportHandle {
                name: primary_name.to_string(),
                established_at: Instant::now(),
                bytes_forwarded: 0,
            },
            Vec::new(),
        );
        Self::new(registry, bridge)
    }

    /// Apply a decider decision. Only [`Decision::Escalate`] drives the
    /// last-resort tier; `Keep`/`Switch` are no-ops here (the primary path
    /// owns them). Selection respects each transport's current health, so an
    /// unhealthy DNS tunnel is never promoted over an available pluggable
    /// transport.
    pub fn apply_decision(&self, decision: &Decision) -> EscalationOutcome {
        let Decision::Escalate = decision else {
            return EscalationOutcome::NoAction;
        };
        let Some(best) = self.registry.select_best() else {
            return EscalationOutcome::NoLastResortAvailable;
        };
        let name = best.name().to_string();
        self.bridge.add_standby(TransportHandle {
            name: name.clone(),
            established_at: Instant::now(),
            bytes_forwarded: 0,
        });
        if self.bridge.promote(&name) {
            tracing::warn!(transport = %name, "resilience: escalated to last-resort transport");
            EscalationOutcome::EscalatedTo(name)
        } else {
            EscalationOutcome::NoLastResortAvailable
        }
    }

    /// Borrow the registry (introspection / metrics).
    #[must_use]
    pub fn registry(&self) -> &TransportRegistry {
        &self.registry
    }

    /// Whether the active transport on the failover bridge has a healthy,
    /// recent handshake (truthful connection check).
    #[must_use]
    pub fn is_active_transport_healthy(&self) -> bool {
        let handle = self.bridge.active();
        // A healthy transport must have been established recently (≤ 5 s)
        // and have a non-zero bytes-forwarded count (indicating real traffic).
        // This matches the blackout isolation contract (§5): no software may
        // claim "connected" without a real recent handshake.
        let recent = handle.established_at.elapsed() <= std::time::Duration::from_secs(5);
        let real_traffic = handle.bytes_forwarded > 0;
        recent && real_traffic
    }

    /// Borrow the bridge (introspection / metrics).
    #[must_use]
    pub fn bridge(&self) -> &FailoverBridge {
        &self.bridge
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Decision;
    use crate::tor::{Transport, TransportRegistry};

    fn controller_with_only_dns(
        dns: DnsTunnelVariant,
    ) -> (ResilienceController, Arc<DnsTunnelTransport>) {
        let reg = TransportRegistry::new();
        let tunnel = Arc::new(DnsTunnelTransport::spawn(dns, "127.0.0.1:18000"));
        let tunnel_for_reg = tunnel.clone();
        reg.register(tunnel_for_reg);
        let bridge = FailoverBridge::new(
            TransportHandle {
                name: "primary".into(),
                established_at: Instant::now(),
                bytes_forwarded: 0,
            },
            Vec::new(),
        );
        (ResilienceController::new(reg, bridge), tunnel)
    }

    #[test]
    fn escalate_promotes_available_last_resort() {
        let (ctrl, tunnel) = controller_with_only_dns(DnsTunnelVariant::MasterDnsVpn);
        tunnel.mark_healthy(true);

        let outcome = ctrl.apply_decision(&Decision::Escalate);
        assert_eq!(
            outcome,
            EscalationOutcome::EscalatedTo("dns-tunnel-masterdns".into())
        );
        assert_eq!(ctrl.bridge().active().name, "dns-tunnel-masterdns");
        assert_eq!(ctrl.bridge().failover_count(), 1);
    }

    #[test]
    fn escalate_with_nothing_available_is_a_no_op() {
        let (ctrl, _tunnel) = controller_with_only_dns(DnsTunnelVariant::VayDns);
        // tunnel stays unhealthy → nothing available.
        let outcome = ctrl.apply_decision(&Decision::Escalate);
        assert_eq!(outcome, EscalationOutcome::NoLastResortAvailable);
        assert_eq!(ctrl.bridge().active().name, "primary"); // unchanged
        assert_eq!(ctrl.bridge().failover_count(), 0);
    }

    #[test]
    fn keep_and_switch_do_not_touch_the_tier() {
        let (ctrl, tunnel) = controller_with_only_dns(DnsTunnelVariant::MasterDnsVpn);
        tunnel.mark_healthy(true);
        assert_eq!(
            ctrl.apply_decision(&Decision::Keep("reality-vision".into())),
            EscalationOutcome::NoAction
        );
        assert_eq!(
            ctrl.apply_decision(&Decision::Switch("hysteria2".into())),
            EscalationOutcome::NoAction
        );
        assert_eq!(ctrl.bridge().active().name, "primary");
    }

    #[test]
    fn end_to_end_decider_dns_anomaly_escalates_to_tier() {
        // Wire the real decider → controller. A DNS-anomaly storm must produce
        // Decision::Escalate, which the controller turns into a tier promotion.
        use crate::decider::{FailKind, LocalDecider};
        use crate::policy::FallbackEngine;

        let mut decider = LocalDecider::new("reality-vision", 64, FallbackEngine::default());
        for _ in 0..30 {
            decider.observe_failure(FailKind::DnsAnomaly);
        }
        assert_eq!(decider.decide(), Decision::Escalate);

        let (ctrl, tunnel) = controller_with_only_dns(DnsTunnelVariant::MasterDnsVpn);
        tunnel.mark_healthy(true);
        let outcome = ctrl.apply_decision(&decider.decide());
        assert!(matches!(outcome, EscalationOutcome::EscalatedTo(_)));
        assert_eq!(ctrl.bridge().active().name, "dns-tunnel-masterdns");
    }

    #[test]
    fn full_tier_registry_contains_all_eight_transports() {
        let ctrl = ResilienceController::with_full_resilience_tier("primary-core");
        let names = ctrl.registry().transport_names();
        // 6 (Arti + 5 PTs) + 3 DNS tunnels + 1 SSH = 10.
        assert_eq!(ctrl.registry().len(), 10);
        assert!(names.contains(&"dns-tunnel-masterdns".to_string()));
        assert!(names.contains(&"dns-tunnel-vaydns-doh".to_string()));
        assert!(names.contains(&"dns-tunnel-noizdns".to_string()));
        assert!(names.contains(&"ssh-socks-tunnel".to_string()));
        assert_eq!(ctrl.bridge().active().name, "primary-core");
        // Negative: Slipstream and standalone-DoH are absent by design.
        assert!(!names.contains(&"slipstream".to_string()));
        assert!(!names.iter().any(|n| n == "doh-transport"));
        // DNS tunnels are unhealthy out of the box → Escalate finds the
        // already-available WebTunnel (priority 20) first, not a DNS tunnel.
        let outcome = ctrl.apply_decision(&Decision::Escalate);
        assert_eq!(outcome, EscalationOutcome::EscalatedTo("webtunnel".into()));
    }

    #[test]
    fn dns_tunnels_override_connect_rtt() {
        let t = DnsTunnelTransport::spawn(DnsTunnelVariant::VayDns, "127.0.0.1:18001");
        t.mark_healthy(true);
        assert_eq!(t.connect().rtt_ms, 800);
    }
}
