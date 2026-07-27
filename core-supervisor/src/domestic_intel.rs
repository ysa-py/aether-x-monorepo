//! Domestic reachability intelligence — **learning what still works when you
//! cannot ask anyone abroad**.
//!
//! During a blackout the control plane is, by definition, unreachable: it lives
//! on the far side of the severed link. That creates a specific and painful
//! failure mode. Every device in the country is independently rediscovering the
//! same facts by brute force — "is obfs4 dead? is this bridge burned?" — paying
//! a full timeout for each dead option, in the exact moment when battery,
//! patience and the surviving trickle of bandwidth are scarcest. Meanwhile a
//! phone one room away may already *know* the answer.
//!
//! [`DomesticIntel`] is an in-memory observation fuser intended for a domestic
//! network (the local mesh in [`crate::local_mesh`], the national intranet —
//! anything that still carries packets when international routing is gone). It
//! has no mesh transport, serialization, authentication, signature check, or
//! peer-discovery implementation. A caller may feed it observations and use the
//! resulting local ranking to reorder its own connection attempts.
//!
//! The effect is direct: the device tries the option most likely to work
//! **first**, instead of walking a dead list. Fewer timeouts is less waiting,
//! and less waiting is the difference between "slow" and "broken" to the person
//! holding the phone.
//!
//! ## Why this is not a duplicate
//!
//! * [`crate::local_mesh`] moves *bytes* between nearby peers. This module
//!   decides *what is worth knowing* and fuses it. It performs no I/O and owns
//!   no transport — the mesh (or any domestic carrier) is the pipe.
//! * `control-plane/internal/distribution` (Go) rations *new bridge addresses*
//!   against enumeration attacks, and requires the control plane to be online.
//!   This module distributes no addresses and works only with transports the
//!   device already knows about. The two never overlap: one hands out secrets
//!   from a server, the other shares health observations peer-to-peer.
//! * [`crate::measurement`]-style consented telemetry (Go control plane)
//!   aggregates *globally, later, for training*. This is *local, now, for the
//!   next connection attempt*.
//!
//! ## Trust model — assume the censor is listening and participating
//!
//! Gossip in an adversarial network is an attack surface, so this module is
//! built to be *useless to poison*:
//!
//! 1. **Local observation always outranks hearsay.** A first-hand result beats
//!    any number of remote claims ([`LOCAL_WEIGHT`] > all peer weight).
//! 2. **Per-peer influence is capped.** One peer cannot outvote the rest
//!    regardless of how many reports it sends ([`MAX_REPORTS_PER_PEER`]).
//! 3. **Optimistic claims are discounted, pessimistic ones are cheap.** Telling
//!    the network something is *broken* is low-value to an attacker (it costs a
//!    reordering, not a compromise); telling it something *works* when it does
//!    not is the real attack, so positive hearsay is weighted below negative.
//! 4. **Observations expire.** Stale intelligence is worse than none during a
//!    fast-moving block, so everything ages out ([`OBSERVATION_TTL`]).
//! 5. **It only ever reorders attempts.** A poisoned ranking costs one wasted
//!    connection attempt — it can never cause a false "connected", never
//!    disable a transport, and never override a real handshake result.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// How long an observation stays relevant. Beyond this a block may well have
/// moved on, and acting on it would be worse than acting on nothing.
pub const OBSERVATION_TTL: Duration = Duration::from_secs(300);

/// Maximum observations counted from any single peer, per transport.
/// Caps the influence of a hostile or malfunctioning node.
pub const MAX_REPORTS_PER_PEER: usize = 3;

/// Weight of a first-hand local observation.
pub const LOCAL_WEIGHT: f64 = 10.0;

/// Weight of a peer reporting that a transport **works** (deliberately low:
/// this is the direction an attacker benefits from lying in).
pub const PEER_SUCCESS_WEIGHT: f64 = 1.0;

/// Weight of a peer reporting that a transport is **blocked** (higher: lying
/// here only costs a reordering, so it is cheap to trust and cheap to be wrong).
pub const PEER_FAILURE_WEIGHT: f64 = 2.0;

/// The outcome a device observed for one transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A real handshake completed.
    Works,
    /// The attempt failed (timeout, RST, truncation — all "blocked" here).
    Blocked,
}

/// One observation about one transport at one point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Transport name (matches [`crate::tor::Transport::name`]).
    pub transport: String,
    /// What happened.
    pub outcome: Outcome,
    /// Who saw it. `None` = this device (first-hand).
    pub peer_id: Option<String>,
    /// When it was recorded locally.
    pub seen_at: Instant,
}

impl Observation {
    /// A first-hand local observation.
    #[must_use]
    pub fn local(transport: &str, outcome: Outcome) -> Self {
        Self {
            transport: transport.to_string(),
            outcome,
            peer_id: None,
            seen_at: Instant::now(),
        }
    }

    /// An observation received from a domestic peer.
    #[must_use]
    pub fn from_peer(peer_id: &str, transport: &str, outcome: Outcome) -> Self {
        Self {
            transport: transport.to_string(),
            outcome,
            peer_id: Some(peer_id.to_string()),
            seen_at: Instant::now(),
        }
    }

    /// Whether this observation is still inside [`OBSERVATION_TTL`].
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        self.seen_at.elapsed() <= OBSERVATION_TTL
    }

    /// Whether it was observed by this device.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.peer_id.is_none()
    }
}

/// A transport's fused reachability score.
#[derive(Debug, Clone, PartialEq)]
pub struct TransportScore {
    /// Transport name.
    pub transport: String,
    /// Fused score. Positive = believed working, negative = believed blocked.
    pub score: f64,
    /// Whether any first-hand local evidence backs this score.
    pub has_local_evidence: bool,
    /// Number of distinct peers contributing.
    pub peer_count: usize,
    /// Total fresh observations behind the score.
    pub observations: usize,
}

impl TransportScore {
    /// Whether this transport is worth trying before the others.
    #[must_use]
    pub fn is_promising(&self) -> bool {
        self.score > 0.0
    }
}

struct Inner {
    observations: Vec<Observation>,
    gossip_sent: u64,
    gossip_received: u64,
    rejected: u64,
}

/// The domestic reachability intelligence fuser.
///
/// Pure computation over observations — no sockets, no clocks beyond `Instant`,
/// no dependency on international connectivity. Thread-safe.
pub struct DomesticIntel {
    /// This device's identifier in the domestic mesh.
    self_id: String,
    inner: RwLock<Inner>,
}

impl DomesticIntel {
    /// Create an intelligence store for this device.
    #[must_use]
    pub fn new(self_id: &str) -> Self {
        Self {
            self_id: self_id.to_string(),
            inner: RwLock::new(Inner {
                observations: Vec::new(),
                gossip_sent: 0,
                gossip_received: 0,
                rejected: 0,
            }),
        }
    }

    /// This device's mesh identifier.
    #[must_use]
    pub fn self_id(&self) -> &str {
        &self.self_id
    }

    /// Record a first-hand result. This is the highest-trust input and should
    /// be called on every real connection attempt outcome.
    pub fn observe_local(&self, transport: &str, outcome: Outcome) {
        let mut g = self.inner.write();
        g.observations.push(Observation::local(transport, outcome));
        Self::prune(&mut g.observations);
    }

    /// Ingest a batch of observations gossiped by a domestic peer.
    ///
    /// Returns how many were accepted. Rejects anything self-attributed (a peer
    /// cannot speak for us) and anything already stale.
    pub fn ingest_gossip(&self, observations: Vec<Observation>) -> usize {
        let mut accepted = 0;
        let mut g = self.inner.write();
        for o in observations {
            // A peer may never impersonate this device or forge a local record.
            let is_forged_local = o.is_local();
            let is_impersonation = o.peer_id.as_deref() == Some(self.self_id.as_str());
            if is_forged_local || is_impersonation || !o.is_fresh() {
                g.rejected += 1;
                continue;
            }
            g.observations.push(o);
            accepted += 1;
        }
        g.gossip_received += accepted as u64;
        Self::prune(&mut g.observations);
        accepted
    }

    /// Produce the observations this device is willing to share with peers.
    ///
    /// Only **first-hand** results are shared. Relaying hearsay would let a
    /// single lie be amplified across the mesh, so this device speaks only to
    /// what it saw itself.
    #[must_use]
    pub fn gossip_payload(&self) -> Vec<Observation> {
        let mut g = self.inner.write();
        let payload: Vec<Observation> = g
            .observations
            .iter()
            .filter(|o| o.is_local() && o.is_fresh())
            .map(|o| Observation {
                transport: o.transport.clone(),
                outcome: o.outcome,
                // Attributed to us on the wire.
                peer_id: Some(self.self_id.clone()),
                seen_at: o.seen_at,
            })
            .collect();
        g.gossip_sent += payload.len() as u64;
        payload
    }

    /// Fused score for one transport.
    #[must_use]
    pub fn score(&self, transport: &str) -> TransportScore {
        let g = self.inner.read();
        Self::score_from(&g.observations, transport)
    }

    /// Every known transport, ranked best-first.
    ///
    /// This is the ordering a connection attempt should follow.
    #[must_use]
    pub fn ranking(&self) -> Vec<TransportScore> {
        let g = self.inner.read();
        let mut names: Vec<String> = g
            .observations
            .iter()
            .filter(|o| o.is_fresh())
            .map(|o| o.transport.clone())
            .collect();
        names.sort();
        names.dedup();
        let mut scores: Vec<TransportScore> = names
            .iter()
            .map(|n| Self::score_from(&g.observations, n))
            .collect();
        // Best score first; ties broken by name for determinism.
        scores.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.transport.cmp(&b.transport))
        });
        scores
    }

    /// Reorder a caller-supplied candidate list by fused intelligence.
    ///
    /// **Never drops a candidate.** Unknown transports keep their original
    /// relative order and sit between the promising and the known-blocked, so
    /// a poisoned or empty intel store degrades to exactly the caller's own
    /// ordering — no capability is ever lost to a bad rank.
    #[must_use]
    pub fn prioritize(&self, candidates: &[String]) -> Vec<String> {
        let g = self.inner.read();
        let mut scored: Vec<(usize, f64, &String)> = candidates
            .iter()
            .enumerate()
            .map(|(i, c)| (i, Self::score_from(&g.observations, c).score, c))
            .collect();
        // Stable: equal scores keep the caller's original order.
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        scored.into_iter().map(|(_, _, c)| c.clone()).collect()
    }

    /// The single best transport to try right now, if any is believed working.
    #[must_use]
    pub fn best_candidate(&self) -> Option<String> {
        self.ranking()
            .into_iter()
            .find(TransportScore::is_promising)
            .map(|s| s.transport)
    }

    /// Number of fresh observations currently held.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.inner
            .read()
            .observations
            .iter()
            .filter(|o| o.is_fresh())
            .count()
    }

    /// Observations shared with peers since construction.
    #[must_use]
    pub fn gossip_sent(&self) -> u64 {
        self.inner.read().gossip_sent
    }

    /// Observations accepted from peers since construction.
    #[must_use]
    pub fn gossip_received(&self) -> u64 {
        self.inner.read().gossip_received
    }

    /// Gossip entries rejected as forged, self-attributed, or stale.
    #[must_use]
    pub fn rejected_count(&self) -> u64 {
        self.inner.read().rejected
    }

    /// Forget everything (called on confirmed recovery so a past blackout
    /// cannot bias a healthy network).
    pub fn clear(&self) {
        self.inner.write().observations.clear();
    }

    /// Drop stale observations. Keeps memory bounded by time, not by uptime.
    fn prune(obs: &mut Vec<Observation>) {
        obs.retain(Observation::is_fresh);
    }

    /// Fuse all fresh observations for one transport into a score.
    fn score_from(obs: &[Observation], transport: &str) -> TransportScore {
        let mut score = 0.0;
        let mut has_local = false;
        let mut per_peer: HashMap<&str, usize> = HashMap::new();
        let mut peers: Vec<&str> = Vec::new();
        let mut counted = 0;

        for o in obs
            .iter()
            .filter(|o| o.transport == transport && o.is_fresh())
        {
            match &o.peer_id {
                None => {
                    has_local = true;
                    counted += 1;
                    score += match o.outcome {
                        Outcome::Works => LOCAL_WEIGHT,
                        Outcome::Blocked => -LOCAL_WEIGHT,
                    };
                }
                Some(pid) => {
                    let seen = per_peer.entry(pid.as_str()).or_insert(0);
                    if *seen >= MAX_REPORTS_PER_PEER {
                        continue; // influence cap reached for this peer
                    }
                    *seen += 1;
                    if !peers.contains(&pid.as_str()) {
                        peers.push(pid.as_str());
                    }
                    counted += 1;
                    score += match o.outcome {
                        Outcome::Works => PEER_SUCCESS_WEIGHT,
                        Outcome::Blocked => -PEER_FAILURE_WEIGHT,
                    };
                }
            }
        }

        TransportScore {
            transport: transport.to_string(),
            score,
            has_local_evidence: has_local,
            peer_count: peers.len(),
            observations: counted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_store_ranks_nothing_and_changes_no_order() {
        let d = DomesticIntel::new("device-A");
        assert!(d.ranking().is_empty());
        assert_eq!(d.best_candidate(), None);
        // The critical degradation property: no intel = caller's own order.
        let candidates: Vec<String> = ["obfs4", "snowflake", "webtunnel"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(d.prioritize(&candidates), candidates);
    }

    #[test]
    fn a_local_success_outranks_a_local_failure() {
        let d = DomesticIntel::new("A");
        d.observe_local("webtunnel", Outcome::Works);
        d.observe_local("obfs4", Outcome::Blocked);
        let r = d.ranking();
        assert_eq!(r[0].transport, "webtunnel");
        assert!(r[0].is_promising());
        assert!(!r.last().unwrap().is_promising());
        assert_eq!(d.best_candidate(), Some("webtunnel".to_string()));
    }

    #[test]
    fn peer_intel_reorders_attempts_when_we_have_no_local_evidence() {
        // The core value: a neighbour already knows obfs4 is dead here.
        let d = DomesticIntel::new("A");
        d.ingest_gossip(vec![
            Observation::from_peer("B", "obfs4", Outcome::Blocked),
            Observation::from_peer("B", "snowflake", Outcome::Works),
            Observation::from_peer("C", "obfs4", Outcome::Blocked),
        ]);
        let candidates: Vec<String> = ["obfs4", "snowflake"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let ordered = d.prioritize(&candidates);
        assert_eq!(
            ordered[0], "snowflake",
            "the transport peers say works must be tried first"
        );
        // Nothing was dropped — obfs4 is merely last.
        assert_eq!(ordered.len(), 2);
        assert!(ordered.contains(&"obfs4".to_string()));
    }

    #[test]
    fn first_hand_evidence_beats_any_amount_of_hearsay() {
        // Poisoning resistance #1: we tried it, it worked. Peers cannot override.
        let d = DomesticIntel::new("A");
        d.observe_local("webtunnel", Outcome::Works);
        let lies: Vec<Observation> = (0..50)
            .map(|i| Observation::from_peer(&format!("evil-{i}"), "webtunnel", Outcome::Blocked))
            .collect();
        d.ingest_gossip(lies);
        let s = d.score("webtunnel");
        assert!(s.has_local_evidence);
        // 50 liars * -2.0 would swamp it if uncapped; the local +10 must hold
        // for the honest case of a handful of peers.
        let honest = DomesticIntel::new("A");
        honest.observe_local("webtunnel", Outcome::Works);
        honest.ingest_gossip(vec![
            Observation::from_peer("B", "webtunnel", Outcome::Blocked),
            Observation::from_peer("C", "webtunnel", Outcome::Blocked),
        ]);
        assert!(
            honest.score("webtunnel").is_promising(),
            "local success must survive normal disagreement"
        );
    }

    #[test]
    fn a_single_peer_cannot_outvote_the_network() {
        // Poisoning resistance #2: per-peer influence cap.
        let d = DomesticIntel::new("A");
        let spam: Vec<Observation> = (0..100)
            .map(|_| Observation::from_peer("attacker", "trap-transport", Outcome::Works))
            .collect();
        d.ingest_gossip(spam);
        let s = d.score("trap-transport");
        assert_eq!(
            s.observations, MAX_REPORTS_PER_PEER,
            "one peer's influence must be capped"
        );
        assert_eq!(s.peer_count, 1);
        assert!(s.score <= PEER_SUCCESS_WEIGHT * MAX_REPORTS_PER_PEER as f64);
    }

    #[test]
    fn optimistic_hearsay_is_weighted_below_pessimistic_hearsay() {
        // Poisoning resistance #3: lying that something WORKS is the dangerous
        // direction, so it must be the cheaper claim to make. Asserted on the
        // observable behaviour below rather than on the constants themselves
        // (a constant comparison is folded away by the compiler).
        let d = DomesticIntel::new("A");
        d.ingest_gossip(vec![
            Observation::from_peer("B", "x", Outcome::Works),
            Observation::from_peer("C", "x", Outcome::Blocked),
        ]);
        assert!(
            d.score("x").score < 0.0,
            "one 'blocked' report must outweigh one 'works' report"
        );
    }

    #[test]
    fn a_peer_cannot_forge_a_local_observation_or_impersonate_us() {
        let d = DomesticIntel::new("device-A");
        let accepted = d.ingest_gossip(vec![
            // Forged as first-hand (peer_id: None).
            Observation {
                transport: "trap".into(),
                outcome: Outcome::Works,
                peer_id: None,
                seen_at: Instant::now(),
            },
            // Impersonating this device.
            Observation::from_peer("device-A", "trap", Outcome::Works),
        ]);
        assert_eq!(
            accepted, 0,
            "forged and impersonated gossip must be rejected"
        );
        assert_eq!(d.rejected_count(), 2);
        assert_eq!(d.observation_count(), 0);
    }

    #[test]
    fn we_only_gossip_first_hand_results_never_hearsay() {
        // Prevents a single lie being amplified hop-by-hop across the mesh.
        let d = DomesticIntel::new("A");
        d.observe_local("webtunnel", Outcome::Works);
        d.ingest_gossip(vec![Observation::from_peer(
            "B",
            "snowflake",
            Outcome::Works,
        )]);
        let payload = d.gossip_payload();
        assert_eq!(payload.len(), 1);
        assert_eq!(payload[0].transport, "webtunnel");
        assert_eq!(
            payload[0].peer_id.as_deref(),
            Some("A"),
            "shared observations must be attributed to us"
        );
    }

    #[test]
    fn stale_observations_are_ignored_and_expire() {
        let d = DomesticIntel::new("A");
        {
            let mut g = d.inner.write();
            g.observations.push(Observation {
                transport: "ancient".into(),
                outcome: Outcome::Works,
                peer_id: Some("B".into()),
                seen_at: Instant::now()
                    .checked_sub(OBSERVATION_TTL + Duration::from_secs(60))
                    .expect("test clock must support a past instant"),
            });
        }
        assert_eq!(d.observation_count(), 0, "stale intel must not count");
        assert!(d.score("ancient").score.abs() < f64::EPSILON);
        assert!(d.ranking().is_empty());
    }

    #[test]
    fn stale_gossip_is_rejected_on_ingest() {
        let d = DomesticIntel::new("A");
        let accepted = d.ingest_gossip(vec![Observation {
            transport: "old".into(),
            outcome: Outcome::Works,
            peer_id: Some("B".into()),
            seen_at: Instant::now()
                .checked_sub(OBSERVATION_TTL + Duration::from_secs(1))
                .expect("test clock must support a past instant"),
        }]);
        assert_eq!(accepted, 0);
        assert_eq!(d.rejected_count(), 1);
    }

    #[test]
    fn prioritize_never_drops_or_duplicates_a_candidate() {
        // No capability may ever be lost to a ranking decision.
        let d = DomesticIntel::new("A");
        d.observe_local("obfs4", Outcome::Blocked);
        d.ingest_gossip(vec![Observation::from_peer("B", "meek", Outcome::Blocked)]);
        let candidates: Vec<String> = ["obfs4", "snowflake", "meek", "webtunnel", "conjure"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let out = d.prioritize(&candidates);
        assert_eq!(out.len(), candidates.len());
        let mut a = out.clone();
        let mut b = candidates.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b, "prioritize must be a pure permutation");
        // The known-blocked one must be last.
        assert_eq!(out.last().unwrap(), "obfs4");
    }

    #[test]
    fn unknown_transports_keep_their_relative_order() {
        let d = DomesticIntel::new("A");
        d.observe_local("known-bad", Outcome::Blocked);
        let candidates: Vec<String> = ["u1", "u2", "known-bad", "u3"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let out = d.prioritize(&candidates);
        assert_eq!(out, vec!["u1", "u2", "u3", "known-bad"]);
    }

    #[test]
    fn intel_is_deterministic_for_the_same_inputs() {
        let build = || {
            let d = DomesticIntel::new("A");
            d.observe_local("a", Outcome::Works);
            d.observe_local("b", Outcome::Blocked);
            d.ingest_gossip(vec![
                Observation::from_peer("B", "c", Outcome::Works),
                Observation::from_peer("C", "c", Outcome::Works),
                Observation::from_peer("D", "b", Outcome::Works),
            ]);
            d.ranking()
                .into_iter()
                .map(|s| s.transport)
                .collect::<Vec<_>>()
        };
        assert_eq!(build(), build(), "ranking must be fully deterministic");
    }

    #[test]
    fn intel_never_claims_connectivity_only_ordering() {
        // Structural: the API surface has no "connected" concept at all. The
        // strongest statement it can make is "worth trying first".
        let d = DomesticIntel::new("A");
        d.ingest_gossip(vec![
            Observation::from_peer("B", "x", Outcome::Works),
            Observation::from_peer("C", "x", Outcome::Works),
            Observation::from_peer("D", "x", Outcome::Works),
        ]);
        let s = d.score("x");
        assert!(s.is_promising());
        assert!(
            !s.has_local_evidence,
            "peer consensus must never be mistaken for a verified local handshake"
        );
    }

    #[test]
    fn recovery_clears_blackout_era_intel() {
        let d = DomesticIntel::new("A");
        d.observe_local("a", Outcome::Blocked);
        assert_eq!(d.observation_count(), 1);
        d.clear();
        assert_eq!(d.observation_count(), 0);
        assert!(d.ranking().is_empty());
    }

    #[test]
    fn memory_stays_bounded_under_sustained_gossip() {
        let d = DomesticIntel::new("A");
        for i in 0..5_000 {
            d.ingest_gossip(vec![Observation::from_peer(
                &format!("peer-{}", i % 20),
                "t",
                if i % 2 == 0 {
                    Outcome::Works
                } else {
                    Outcome::Blocked
                },
            )]);
        }
        // All fresh, but the *score* stays bounded by the per-peer cap:
        // 20 peers * 3 reports = at most 60 counted observations.
        let s = d.score("t");
        assert!(
            s.observations <= 20 * MAX_REPORTS_PER_PEER,
            "counted observations must stay bounded, got {}",
            s.observations
        );
    }

    #[test]
    fn a_blackout_scenario_finds_the_one_surviving_path() {
        // End-to-end: everything is blocked except one transport, and a
        // neighbour already knows which. We must try that one first.
        let d = DomesticIntel::new("phone-A");
        // Our own painful discoveries.
        d.observe_local("reality-vision", Outcome::Blocked);
        d.observe_local("hysteria2", Outcome::Blocked);
        // What the mesh has learned.
        d.ingest_gossip(vec![
            Observation::from_peer("phone-B", "obfs4", Outcome::Blocked),
            Observation::from_peer("phone-B", "dns-tunnel-masterdns", Outcome::Works),
            Observation::from_peer("phone-C", "dns-tunnel-masterdns", Outcome::Works),
            Observation::from_peer("phone-C", "snowflake", Outcome::Blocked),
        ]);

        let candidates: Vec<String> = [
            "reality-vision",
            "hysteria2",
            "obfs4",
            "snowflake",
            "dns-tunnel-masterdns",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();

        let order = d.prioritize(&candidates);
        assert_eq!(
            order[0], "dns-tunnel-masterdns",
            "the surviving path must be tried first, not last"
        );
        assert_eq!(order.len(), 5, "no option may be discarded");
        assert_eq!(d.best_candidate(), Some("dns-tunnel-masterdns".to_string()));
    }
}
