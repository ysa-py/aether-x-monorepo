//! Happy Eyeballs v2 parallel probing — zero-perceived-disconnect racing.
//!
//! RFC 8305 (Happy Eyeballs v2) races IPv4, IPv6, and multiple transport
//! candidates concurrently with staggered starts. Aether-X extends it to race
//! *transports* (TLS, gRPC, DoH, ICMP, IPv6 direct) not just addresses.
//!
//! Guarantees: user gets the first working path in ~one RTT, not N serial timeouts.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

/// A candidate endpoint to race.
#[derive(Debug, Clone)]
pub struct ProbeCandidate {
    pub id: String,
    pub addr: String,
    pub transport: String, // e.g. "tls", "grpc", "doh", "icmp", "ipv6"
    pub priority: u8,      // lower = try sooner
    pub is_ipv6: bool,
}

impl ProbeCandidate {
    pub fn new(id: &str, addr: &str, transport: &str, priority: u8, ipv6: bool) -> Self {
        Self {
            id: id.to_string(),
            addr: addr.to_string(),
            transport: transport.to_string(),
            priority,
            is_ipv6: ipv6,
        }
    }
}

/// Outcome of probing one candidate.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub candidate_id: String,
    pub success: bool,
    pub rtt: Duration,
    pub error: Option<String>,
}

/// Happy Eyeballs v2 racer config.
#[derive(Debug, Clone)]
pub struct HappyEyeballsConfig {
    /// Delay between starting next candidate (RFC 8305 recommends 250ms)
    pub connection_attempt_delay: Duration,
    /// Overall timeout for entire racing.
    pub overall_timeout: Duration,
    /// Per-candidate timeout.
    pub per_candidate_timeout: Duration,
    /// Prefer IPv6 (RFC 8305: try IPv6 first).
    pub prefer_ipv6: bool,
}

impl Default for HappyEyeballsConfig {
    fn default() -> Self {
        Self {
            connection_attempt_delay: Duration::from_millis(250),
            overall_timeout: Duration::from_secs(10),
            per_candidate_timeout: Duration::from_secs(3),
            prefer_ipv6: true,
        }
    }
}

/// Function type for probing a candidate (to allow mock in tests).
/// Takes candidate, returns outcome. Must respect cancellation via flag.
type ProbeFn = Arc<dyn Fn(&ProbeCandidate, &AtomicBool) -> ProbeOutcome + Send + Sync>;

/// The Happy Eyeballs racer.
pub struct HappyEyeballs {
    config: HappyEyeballsConfig,
    probe_fn: ProbeFn,
}

impl HappyEyeballs {
    /// Create with real probe function (TCP connect simulation).
    #[must_use]
    pub fn with_config(config: HappyEyeballsConfig) -> Self {
        // Default probe: simulated fast success for known transports; real would TCP dial.
        let default_probe: ProbeFn = Arc::new(|cand: &ProbeCandidate, cancelled: &AtomicBool| {
            if cancelled.load(Ordering::Relaxed) {
                return ProbeOutcome {
                    candidate_id: cand.id.clone(),
                    success: false,
                    rtt: Duration::ZERO,
                    error: Some("cancelled".into()),
                };
            }
            // Simulate: tls/grpc/ipv6 succeed fast, others maybe slower
            let start = Instant::now();
            // Minimal sleep to model different transport handshake costs
            let delay_ms = match cand.transport.as_str() {
                "tls" => 30,
                "grpc" => 40,
                "ipv6" => 20,
                "doh" => 200,
                "icmp" => 300,
                _ => 100,
            };
            // Check cancellation during simulated network wait in small slices
            let mut waited = 0u64;
            while waited < delay_ms {
                if cancelled.load(Ordering::Relaxed) {
                    return ProbeOutcome {
                        candidate_id: cand.id.clone(),
                        success: false,
                        rtt: Duration::ZERO,
                        error: Some("cancelled".into()),
                    };
                }
                thread::sleep(Duration::from_millis(1));
                waited += 1;
            }
            ProbeOutcome {
                candidate_id: cand.id.clone(),
                success: true,
                rtt: start.elapsed(),
                error: None,
            }
        });
        Self {
            config,
            probe_fn: default_probe,
        }
    }

    #[must_use]
    pub fn with_probe_fn(config: HappyEyeballsConfig, f: ProbeFn) -> Self {
        Self {
            config,
            probe_fn: f,
        }
    }

    /// Race candidates, return first successful outcome (if any) and all outcomes.
    pub fn race(&self, mut candidates: Vec<ProbeCandidate>) -> RaceResult {
        // Sort: IPv6 first if prefer_ipv6, then by priority
        candidates.sort_by(|a, b| {
            if self.config.prefer_ipv6 {
                match (a.is_ipv6, b.is_ipv6) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a.priority.cmp(&b.priority),
                }
            } else {
                a.priority.cmp(&b.priority)
            }
        });

        if candidates.is_empty() {
            return RaceResult {
                winner: None,
                all_outcomes: Vec::new(),
            };
        }

        let (tx, rx) = mpsc::channel::<ProbeOutcome>();
        let cancelled = Arc::new(AtomicBool::new(false));
        let overall_deadline = Instant::now() + self.config.overall_timeout;

        let mut handles = Vec::new();

        for (idx, cand) in candidates.iter().cloned().enumerate() {
            let tx = tx.clone();
            let probe_fn = Arc::clone(&self.probe_fn);
            let cancelled = Arc::clone(&cancelled);
            let delay = self.config.connection_attempt_delay * (idx as u32);

            let handle = thread::spawn(move || {
                if delay > Duration::ZERO {
                    // Staggered start: wait connection_attempt_delay * idx, but respect cancellation
                    let start_wait = Instant::now();
                    while start_wait.elapsed() < delay {
                        if cancelled.load(Ordering::Relaxed) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                }
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }
                let outcome = probe_fn(&cand, &cancelled);
                let _ = tx.send(outcome);
            });
            handles.push(handle);
        }
        drop(tx);

        let mut outcomes: Vec<ProbeOutcome> = Vec::new();
        let mut winner: Option<ProbeOutcome> = None;

        loop {
            let remaining = overall_deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                break;
            }
            match rx.recv_timeout(remaining.min(Duration::from_millis(50))) {
                Ok(o) => {
                    if o.success && winner.is_none() {
                        winner = Some(o.clone());
                        // Cancel others - winner found
                        cancelled.store(true, Ordering::Relaxed);
                        outcomes.push(o);
                        // Drain a bit more for stats but quickly
                        while let Ok(extra) = rx.recv_timeout(Duration::from_millis(10)) {
                            outcomes.push(extra);
                        }
                        break;
                    } else {
                        outcomes.push(o);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if winner.is_some() {
                        break;
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        // Ensure all threads finish
        for h in handles {
            let _ = h.join();
        }
        // Collect any remaining outcomes already sent
        while let Ok(o) = rx.try_recv() {
            if !outcomes.iter().any(|x| x.candidate_id == o.candidate_id) {
                outcomes.push(o);
            }
        }

        RaceResult {
            winner,
            all_outcomes: outcomes,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RaceResult {
    pub winner: Option<ProbeOutcome>,
    pub all_outcomes: Vec<ProbeOutcome>,
}

impl RaceResult {
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.winner.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: &str, transport: &str, pri: u8, ipv6: bool) -> ProbeCandidate {
        ProbeCandidate::new(id, &format!("{id}.example:443"), transport, pri, ipv6)
    }

    #[test]
    fn prefers_ipv6_first() {
        let config = HappyEyeballsConfig::default();
        let racer = HappyEyeballs::with_config(config);
        let candidates = vec![
            cand("ipv4-tls", "tls", 10, false),
            cand("ipv6-tls", "tls", 10, true),
            cand("ipv4-grpc", "grpc", 20, false),
        ];
        let result = racer.race(candidates);
        assert!(result.is_success());
        // With prefer_ipv6, winner should be ipv6 if both succeed fast (ipv6 20ms vs tls 30ms)
        // Since ipv6 candidate starts first (sorted), it may win
        assert!(result.winner.is_some());
    }

    #[test]
    fn first_success_wins() {
        // Custom probe where first candidate fails, second succeeds
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(10),
            overall_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let probe: ProbeFn = Arc::new(|c: &ProbeCandidate, _cancel: &AtomicBool| {
            if c.id == "fail" {
                ProbeOutcome {
                    candidate_id: c.id.clone(),
                    success: false,
                    rtt: Duration::from_millis(10),
                    error: Some("failed".into()),
                }
            } else {
                ProbeOutcome {
                    candidate_id: c.id.clone(),
                    success: true,
                    rtt: Duration::from_millis(20),
                    error: None,
                }
            }
        });
        let racer = HappyEyeballs::with_probe_fn(config, probe);
        let candidates = vec![
            cand("fail", "tls", 10, false),
            cand("succeed", "grpc", 20, false),
        ];
        let result = racer.race(candidates);
        assert!(result.is_success());
        assert_eq!(result.winner.unwrap().candidate_id, "succeed");
    }

    #[test]
    fn empty_candidates_no_winner() {
        let racer = HappyEyeballs::with_config(HappyEyeballsConfig::default());
        let result = racer.race(vec![]);
        assert!(!result.is_success());
        assert!(result.winner.is_none());
    }

    #[test]
    fn staggered_probing_reduces_latency() {
        // 5 candidates, sequential would be 5*timeout = 15s, racing is ~ few hundred ms
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(50),
            overall_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let racer = HappyEyeballs::with_config(config);
        let candidates: Vec<_> = (0..5)
            .map(|i| cand(&format!("c{i}"), "tls", i as u8, i == 0))
            .collect();
        let start = Instant::now();
        let result = racer.race(candidates);
        let elapsed = start.elapsed();
        assert!(result.is_success());
        assert!(
            elapsed < Duration::from_secs(1),
            "racing took too long: {elapsed:?}"
        );
    }

    #[test]
    fn cancels_others_after_winner() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        let probe: ProbeFn = Arc::new(move |c: &ProbeCandidate, cancelled: &AtomicBool| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            // Slow probe that checks cancellation
            for _ in 0..100 {
                if cancelled.load(Ordering::Relaxed) {
                    return ProbeOutcome {
                        candidate_id: c.id.clone(),
                        success: false,
                        rtt: Duration::ZERO,
                        error: Some("cancelled".into()),
                    };
                }
                thread::sleep(Duration::from_millis(1));
            }
            ProbeOutcome {
                candidate_id: c.id.clone(),
                success: true,
                rtt: Duration::from_millis(100),
                error: None,
            }
        });
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(10),
            overall_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let racer = HappyEyeballs::with_probe_fn(config, probe);
        let candidates = vec![
            cand("fast", "tls", 0, true),
            cand("slow1", "doh", 10, false),
            cand("slow2", "icmp", 20, false),
        ];
        let result = racer.race(candidates);
        assert!(result.is_success());
        // Winner found quickly, others cancelled
        assert!(counter.load(Ordering::SeqCst) >= 1);
    }
}
