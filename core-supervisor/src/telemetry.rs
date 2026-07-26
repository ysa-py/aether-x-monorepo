//! Telemetry collection & fan-out.
//!
//! Adapters/stubs push raw events into a [`Collector`]; the gRPC server pulls
//! a broadcast stream from it and forwards batches to the control plane. This
//! decouples *event production* (hot path, per-connection) from *event
//! transport* (gRPC stream, batched).

use std::time::Duration;

use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

use crate::aether::telemetry::v1::TelemetryEvent;

/// Capacity of the broadcast channel. Events produced with no receiver are
/// dropped (telemetry is best-effort; we must never block the data path).
const CHANNEL_CAPACITY: usize = 4096;

/// A best-effort telemetry collector.
#[derive(Clone)]
pub struct Collector {
    tx: broadcast::Sender<TelemetryEvent>,
}

impl Collector {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx }
    }

    /// Push an event. Non-blocking; silently drops if the channel is full.
    pub fn record(&self, ev: TelemetryEvent) {
        // send fails only when there are no receivers — that's fine.
        let _ = self.tx.send(ev);
    }

    /// A stream of events for the gRPC `StreamTelemetry` RPC.
    pub fn subscribe(&self) -> BroadcastStream<TelemetryEvent> {
        BroadcastStream::new(self.tx.subscribe())
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple rolling-window success-rate calculator, used to feed the fallback
/// engine cheaply without touching ClickHouse.
#[derive(Debug, Clone)]
pub struct RollingSuccess {
    samples: Vec<bool>,
    idx: usize,
    filled: bool,
}

impl RollingSuccess {
    pub fn new(window: usize) -> Self {
        Self {
            samples: vec![false; window.max(1)],
            idx: 0,
            filled: false,
        }
    }

    pub fn record(&mut self, success: bool) {
        self.samples[self.idx] = success;
        self.idx = (self.idx + 1) % self.samples.len();
        if self.idx == 0 {
            self.filled = true;
        }
    }

    /// (count, success_rate).
    pub fn stats(&self) -> (u32, f64) {
        let n = if self.filled {
            self.samples.len() as u32
        } else {
            self.idx as u32
        };
        if n == 0 {
            return (0, 1.0);
        }
        let wins = self.samples.iter().filter(|b| **b).count() as f64;
        (n, wins / f64::from(n))
    }
}

/// How long to wait before flushing a telemetry batch.
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(200);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolling_success_basic() {
        let mut r = RollingSuccess::new(4);
        assert_eq!(r.stats().0, 0);
        for ok in [true, true, false, true] {
            r.record(ok);
        }
        let (n, rate) = r.stats();
        assert_eq!(n, 4);
        assert!((rate - 0.75).abs() < 1e-9);
    }

    #[test]
    fn rolling_success_wraps() {
        let mut r = RollingSuccess::new(2);
        r.record(true);
        r.record(false);
        r.record(true);
        let (n, rate) = r.stats();
        assert_eq!(n, 2);
        assert!((rate - 0.5).abs() < 1e-9);
    }

    #[tokio::test]
    async fn collector_is_non_blocking_when_no_subscribers() {
        let c = Collector::new();
        // No subscribers — pushing must not panic or block.
        for _ in 0..10_000 {
            c.record(TelemetryEvent::default());
        }
    }
}
