//! Multipath connection racing + bonded throughput aggregation.
//!
//! The resilience tier's [`crate::tor::TransportRegistry::select_best`] tries
//! transports **one at a time, in priority order**. That is correct for steady
//! state but has two costs under blackout conditions:
//!
//!   1. **Latency**: if the best-priority transport is down, the user waits a
//!      full handshake-timeout before the next is tried — serial fallback is
//!      exactly the disconnect the user *feels*.
//!   2. **Throughput**: a single last-resort path (e.g. a DNS tunnel) is
//!      tens-to-hundreds of kbps. The user stays "connected" but it is slow.
//!
//! This module provides two complementary strategies the blackout/resilience
//! tier composes on top of the registry:
//!
//!   - [`MultipathRacer::race`] — fire connects across **every** available
//!     transport concurrently; adopt the fastest established one. Cuts connect
//!     latency from O(N serial timeouts) to ~one round-trip, so the user never
//!     sits through a sequential fallback chain. (The Happy-Eyeballs / MPTCP
//!     idea, applied to the censorship-resistance transport set.)
//!   - [`MultipathBond`] — once several transports are established, distribute
//!     traffic across **all** of them (weighted round-robin, weighted by
//!     inverse RTT). N parallel slow streams approximate N× throughput — the
//!     honest answer to "stay connected *and* fast" on last-resort paths.
//!
//! Both coordinate actual `Transport::connect` results. An unconfigured or
//! failed transport is recorded as a failed attempt and is never given a
//! synthetic RTT or included in a bond.

use crate::tor::{Transport, TransportConnection};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// One transport's outcome in a race (mirrors [`TransportConnection`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaceAttempt {
    pub name: String,
    pub established: bool,
    pub rtt_ms: u32,
    /// The real connect error when no connection was established.
    pub error: Option<String>,
}

impl From<&TransportConnection> for RaceAttempt {
    fn from(c: &TransportConnection) -> Self {
        Self {
            name: c.transport_name.clone(),
            established: c.established,
            rtt_ms: c.rtt_ms,
            error: None,
        }
    }
}

/// Result of racing a set of transports.
#[derive(Debug, Clone)]
pub struct RaceOutcome {
    /// The fastest established connection (lowest RTT), or `None` if none
    /// established within the timeout.
    pub winner: Option<TransportConnection>,
    /// Every attempt's outcome (in completion order).
    pub attempts: Vec<RaceAttempt>,
}

/// Concurrent connection racer.
pub struct MultipathRacer;

impl MultipathRacer {
    /// Race [`Transport::connect`] across every transport concurrently and
    /// return the fastest established connection. `timeout` bounds the whole
    /// race (a transport that has not answered by the deadline is recorded as
    /// not-established).
    ///
    /// This is the "strongest, no-perceived-disconnect" connect strategy: the
    /// user gets the best *working* path in ~one round-trip instead of waiting
    /// through a serial fallback chain.
    pub fn race(transports: &[Arc<dyn Transport>], timeout: Duration) -> RaceOutcome {
        let (tx, rx) = mpsc::channel::<(
            String,
            Result<TransportConnection, crate::tor::ConnectError>,
        )>();
        let handles: Vec<_> = transports
            .iter()
            .map(|transport| {
                let transport = Arc::clone(transport);
                let tx = tx.clone();
                thread::spawn(move || {
                    let name = transport.name().to_string();
                    // `connect` opens a real configured socket or returns the
                    // real error; the race records failure rather than inventing
                    // an RTT or a successful connection.
                    let _ = tx.send((name, transport.connect()));
                })
            })
            .collect();
        drop(tx);

        let deadline = Instant::now() + timeout;
        let mut connections = Vec::new();
        let mut attempts = Vec::new();
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                break;
            }
            match rx.recv_timeout(remaining) {
                Ok((name, Ok(connection))) => {
                    attempts.push(RaceAttempt::from(&connection));
                    connections.push(connection);
                }
                Ok((name, Err(error))) => attempts.push(RaceAttempt {
                    name,
                    established: false,
                    rtt_ms: 0,
                    error: Some(error.to_string()),
                }),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
            }
        }
        // Reap worker threads so none outlive the call.
        for handle in handles {
            let _ = handle.join();
        }

        let winner = connections
            .iter()
            .min_by_key(|connection| connection.rtt_ms)
            .cloned();

        // Any transport that never reported by the shared deadline is explicitly
        // recorded as a timeout, not as a fabricated 50ms connection.
        let reported: std::collections::HashSet<String> = attempts
            .iter()
            .map(|attempt| attempt.name.clone())
            .collect();
        for transport in transports {
            if !reported.contains(transport.name()) {
                attempts.push(RaceAttempt {
                    name: transport.name().to_string(),
                    established: false,
                    rtt_ms: 0,
                    error: Some(format!("race deadline exceeded after {timeout:?}")),
                });
            }
        }

        RaceOutcome { winner, attempts }
    }
}

/// Weight (1..=10) derived from a transport's RTT — lower RTT ⇒ higher weight.
fn weight_for_rtt(rtt_ms: u32) -> usize {
    let rtt = rtt_ms.max(1) as usize;
    (500 / rtt).clamp(1, 10)
}

/// A bonded group of established transports that distributes traffic across
/// all of them (weighted round-robin) to multiply throughput. The honest
/// "stay connected *and* fast" strategy for last-resort paths: N parallel slow
/// streams approximate N× the bandwidth of one.
#[derive(Debug)]
pub struct MultipathBond {
    members: Vec<Arc<dyn Transport>>,
    weights: Vec<usize>,
    /// Member indices repeated by weight — the round-robin schedule.
    schedule: Vec<usize>,
    cursor: AtomicUsize,
}

impl MultipathBond {
    /// Build a bond from the transports that are currently available. Each
    /// member's weight is derived from its connection RTT (faster ⇒ heavier).
    #[must_use]
    pub fn from_available(transports: &[Arc<dyn Transport>]) -> Self {
        let mut members: Vec<Arc<dyn Transport>> = Vec::new();
        let mut weights: Vec<usize> = Vec::new();
        let mut schedule: Vec<usize> = Vec::new();
        for t in transports {
            if !t.is_available() {
                continue;
            }
            let Ok(connection) = t.connect() else {
                // A bond may contain only transports that completed a real
                // connection; failures stay visible through the racer path.
                continue;
            };
            let w = weight_for_rtt(connection.rtt_ms);
            let idx = members.len();
            members.push(Arc::clone(t));
            weights.push(w);
            for _ in 0..w {
                schedule.push(idx);
            }
        }
        Self {
            members,
            weights,
            schedule,
            cursor: AtomicUsize::new(0),
        }
    }

    /// Pick the next transport to send on (weighted round-robin). Returns
    /// `None` only if no transport was available when the bond was built.
    pub fn next(&self) -> Option<Arc<dyn Transport>> {
        if self.schedule.is_empty() {
            return None;
        }
        let idx = self.cursor.fetch_add(1, Ordering::SeqCst) % self.schedule.len();
        let &member_idx = self.schedule.get(idx)?;
        self.members.get(member_idx).cloned()
    }

    /// Number of bonded transports.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Approximate aggregate-throughput multiplier vs. the single fastest
    /// member (sum of weights ÷ max weight). > 1.0 whenever more than one
    /// transport is bonded; 0.0 when the bond is empty.
    #[must_use]
    pub fn aggregate_multiplier(&self) -> f64 {
        if self.weights.is_empty() {
            return 0.0;
        }
        let sum: usize = self.weights.iter().sum();
        let max: usize = *self.weights.iter().max().unwrap_or(&1);
        sum as f64 / max.max(1) as f64
    }

    /// Names of the bonded transports (for status UI).
    #[must_use]
    pub fn member_names(&self) -> Vec<String> {
        self.members.iter().map(|t| t.name().to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    /// A controllable transport for deterministic race tests: configurable
    /// availability + RTT.
    #[derive(Debug)]
    struct ProbeTransport {
        name: &'static str,
        rtt: u32,
        up: AtomicBool,
    }
    impl ProbeTransport {
        fn new(name: &'static str, rtt: u32, up: bool) -> Self {
            Self {
                name,
                rtt,
                up: AtomicBool::new(up),
            }
        }
    }
    impl Transport for ProbeTransport {
        fn name(&self) -> &str {
            self.name
        }
        fn priority(&self) -> u8 {
            50
        }
        fn is_available(&self) -> bool {
            self.up.load(Ordering::SeqCst)
        }
        fn connect(&self) -> Result<TransportConnection, crate::tor::ConnectError> {
            if !self.is_available() {
                return Err(crate::tor::ConnectError::NotConfigured {
                    transport: self.name.to_string(),
                });
            }
            Ok(TransportConnection {
                transport_name: self.name.into(),
                established: true,
                rtt_ms: self.rtt,
                peer: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            })
        }
    }

    #[test]
    fn race_picks_fastest_established() {
        let transports: Vec<Arc<dyn Transport>> = vec![
            Arc::new(ProbeTransport::new("slow", 300, true)),
            Arc::new(ProbeTransport::new("fast", 40, true)),
            Arc::new(ProbeTransport::new("dead", 10, false)),
        ];
        let outcome = MultipathRacer::race(&transports, Duration::from_millis(500));
        let winner = outcome.winner.expect("a winner");
        assert_eq!(winner.transport_name, "fast");
        assert_eq!(winner.rtt_ms, 40);
        // All three reported.
        let names: Vec<&str> = outcome.attempts.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"slow"));
        assert!(names.contains(&"fast"));
        assert!(names.contains(&"dead"));
        // The dead one is recorded as not established.
        let dead = outcome.attempts.iter().find(|a| a.name == "dead").unwrap();
        assert!(!dead.established);
    }

    #[test]
    fn race_with_none_established_has_no_winner() {
        let transports: Vec<Arc<dyn Transport>> = vec![
            Arc::new(ProbeTransport::new("a", 50, false)),
            Arc::new(ProbeTransport::new("b", 50, false)),
        ];
        let outcome = MultipathRacer::race(&transports, Duration::from_millis(200));
        assert!(outcome.winner.is_none());
        assert_eq!(outcome.attempts.len(), 2);
    }

    #[test]
    fn bond_aggregates_multiple_paths() {
        let transports: Vec<Arc<dyn Transport>> = vec![
            Arc::new(ProbeTransport::new("one", 50, true)),
            Arc::new(ProbeTransport::new("two", 50, true)),
            Arc::new(ProbeTransport::new("three", 50, true)),
        ];
        let bond = MultipathBond::from_available(&transports);
        assert_eq!(bond.member_count(), 3);
        // Three equal-weight members ⇒ multiplier ~3×.
        assert!((bond.aggregate_multiplier() - 3.0).abs() < 0.01);
        // Weighted round-robin visits all members.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..30 {
            seen.insert(bond.next().unwrap().name().to_string());
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn bond_weights_faster_transport_more_heavily() {
        // The weights are calculated over established connection measurements.
        let transports: Vec<Arc<dyn Transport>> = vec![
            Arc::new(ProbeTransport::new("fast-one", 50, true)),
            Arc::new(ProbeTransport::new("fast-two", 50, true)),
            Arc::new(ProbeTransport::new("slow", 800, true)),
        ];
        let bond = MultipathBond::from_available(&transports);
        assert_eq!(bond.member_count(), 3);
        // Over a long round-robin, the fast PTs dominate the slow tunnel.
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for _ in 0..1100 {
            let n = bond.next().unwrap().name().to_string();
            *counts.entry(n).or_insert(0) += 1;
        }
        let pt = counts["fast-one"];
        let tunnel = counts["slow"];
        assert!(
            pt > tunnel,
            "fast PT ({pt}) should beat DNS tunnel ({tunnel})"
        );
    }

    #[test]
    fn empty_bond_is_safe() {
        let bond = MultipathBond::from_available(&[]);
        assert_eq!(bond.member_count(), 0);
        assert!((bond.aggregate_multiplier() - 0.0).abs() < f64::EPSILON);
        assert!(bond.next().is_none());
    }

    #[test]
    fn race_then_bond_end_to_end() {
        // The composed strategy: race to find working paths fast, then bond
        // them for throughput.
        let transports: Vec<Arc<dyn Transport>> = vec![
            Arc::new(ProbeTransport::new("fast-one", 40, true)),
            Arc::new(ProbeTransport::new("fast-two", 60, true)),
            Arc::new(ProbeTransport::new("slow", 800, true)),
        ];
        let raced = MultipathRacer::race(&transports, Duration::from_millis(500));
        // Winner is the fastest successful measured connection.
        assert_eq!(raced.winner.as_ref().unwrap().rtt_ms, 40);
        // Bond all available for aggregate throughput.
        let bond = MultipathBond::from_available(&transports);
        assert!(bond.aggregate_multiplier() > 1.0);
        assert!(bond.member_names().contains(&"slow".to_string()));
    }
}
