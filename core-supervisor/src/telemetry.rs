//! Telemetry collection & fan-out.
//!
//! Adapters/stubs push raw events into a [`Collector`]; the gRPC server pulls
//! a broadcast stream from it and forwards batches to the control plane. This
//! decouples *event production* (hot path, per-connection) from *event
//! transport* (gRPC stream, batched).
//!
//! ## Store-and-forward on the live path
//!
//! When the control plane is *not* attached (blackout, restart, network
//! partition) a broadcast send has no receiver and the event used to vanish.
//! A [`Collector`] built with [`Collector::with_store_and_forward`] instead
//! hands those events to a bounded queue which is disk-backed only through a
//! sealed [`crate::store_and_forward::StoreAndForward`] spool, and replays them the
//! moment a subscriber attaches. This is the same contract as the Go control
//! plane's `AETHER_TELEMETRY_SPOOL` disk spool
//! (`control-plane/internal/telemetry/clickhouse.go`): buffer on the floor,
//! drain on reconnect, never grow without bound.

use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

use crate::aether::telemetry::v1::TelemetryEvent;
use crate::store_and_forward::{Priority, StoreAndForward};

/// Capacity of the broadcast channel. Events produced with no receiver are
/// dropped (telemetry is best-effort; we must never block the data path).
const CHANNEL_CAPACITY: usize = 4096;

/// A best-effort telemetry collector.
#[derive(Clone)]
pub struct Collector {
    tx: broadcast::Sender<TelemetryEvent>,
    /// Optional durable spool used while no subscriber is attached.
    spool: Option<Arc<StoreAndForward>>,
}

impl Collector {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx, spool: None }
    }

    /// A collector that persists events to `queue` whenever the control plane
    /// is detached, and replays them on the next [`Collector::subscribe`].
    #[must_use]
    pub fn with_store_and_forward(queue: Arc<StoreAndForward>) -> Self {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            tx,
            spool: Some(queue),
        }
    }

    /// The store-and-forward queue backing this collector, if any.
    #[must_use]
    pub fn store_and_forward(&self) -> Option<&Arc<StoreAndForward>> {
        self.spool.as_ref()
    }

    /// Push an event. Non-blocking.
    ///
    /// If a subscriber exists the event goes straight onto the broadcast
    /// channel. If none does — and a spool is configured — the event is
    /// queued (bounded + persisted) instead of being dropped.
    pub fn record(&self, ev: TelemetryEvent) {
        // Fast path: no spool configured ⇒ behave exactly as before (a single
        // move into the broadcast channel, no clone on the data path).
        let Some(spool) = self.spool.as_ref() else {
            let _ = self.tx.send(ev);
            return;
        };
        // With a spool, we must keep the event if the send finds no receiver.
        // `broadcast::send` returns the value back inside the error, so this
        // still costs no clone in the common (attached) case.
        if let Err(broadcast::error::SendError(ev)) = self.tx.send(ev) {
            // The capacity bound may refuse the item; that is a truthful drop
            // with a counter, not silent unbounded growth.
            let _ = spool.try_enqueue(Priority::Control, ev.encode_to_vec());
        }
    }

    /// Number of events currently held for a detached control plane.
    #[must_use]
    pub fn spooled(&self) -> usize {
        self.spool.as_ref().map_or(0, |s| s.pending())
    }

    /// Drain the spool into decoded events, in flush order (control lane
    /// first). Called when a subscriber attaches; safe to call with no spool.
    pub fn drain_spooled(&self) -> Vec<TelemetryEvent> {
        let Some(spool) = self.spool.as_ref() else {
            return Vec::new();
        };
        spool
            .flush()
            .into_iter()
            .filter_map(|item| TelemetryEvent::decode(item.data.as_slice()).ok())
            .collect()
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
        assert_eq!(c.spooled(), 0, "no spool configured ⇒ nothing buffered");
    }

    #[tokio::test]
    async fn detached_control_plane_events_are_spooled_not_lost() {
        use crate::store_and_forward::QueueLimits;

        let queue = Arc::new(StoreAndForward::with_limits(QueueLimits::default()));
        let c = Collector::with_store_and_forward(queue.clone());

        // Nobody is subscribed: the control plane is detached.
        for i in 0..5 {
            c.record(TelemetryEvent {
                node_id: format!("node-{i}"),
                ..Default::default()
            });
        }
        assert_eq!(c.spooled(), 5, "events must be queued, not dropped");

        // Control plane attaches and drains the backlog.
        let replayed = c.drain_spooled();
        assert_eq!(replayed.len(), 5);
        assert_eq!(replayed[0].node_id, "node-0");
        assert_eq!(replayed[4].node_id, "node-4");
        assert_eq!(c.spooled(), 0);
    }

    #[tokio::test]
    async fn attached_subscriber_bypasses_the_spool() {
        use crate::store_and_forward::QueueLimits;

        let queue = Arc::new(StoreAndForward::with_limits(QueueLimits::default()));
        let c = Collector::with_store_and_forward(queue.clone());
        let _rx = c.subscribe(); // a live control-plane stream

        c.record(TelemetryEvent::default());
        assert_eq!(c.spooled(), 0, "live path must not touch disk/queue");
    }

    #[tokio::test]
    async fn spool_stays_bounded_under_a_long_blackout() {
        use crate::store_and_forward::{OverflowPolicy, QueueLimits};

        let limits = QueueLimits {
            max_items: 32,
            max_bytes: 1 << 16,
            policy: OverflowPolicy::EvictOldest,
        };
        let queue = Arc::new(StoreAndForward::with_limits(limits));
        let c = Collector::with_store_and_forward(queue.clone());
        for _ in 0..10_000 {
            c.record(TelemetryEvent::default());
        }
        assert!(c.spooled() <= 32, "no unbounded growth during blackout");
        assert!(queue.pending_bytes() <= limits.max_bytes);
    }

    #[tokio::test]
    async fn spooled_telemetry_survives_a_crash() {
        use crate::store_and_forward::{Aes256GcmSpoolSealer, QueueLimits, SpoolSealer};

        let sealer: Arc<dyn SpoolSealer> =
            Arc::new(Aes256GcmSpoolSealer::from_key_bytes([0xA5; 32]).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telemetry-spool.jsonl");
        {
            let queue = Arc::new(
                StoreAndForward::open(&path, QueueLimits::default(), Arc::clone(&sealer)).unwrap(),
            );
            let c = Collector::with_store_and_forward(queue);
            c.record(TelemetryEvent {
                node_id: "survivor".into(),
                ..Default::default()
            });
            // Crash: no flush, no graceful shutdown.
        }
        let queue = Arc::new(
            StoreAndForward::open(&path, QueueLimits::default(), Arc::clone(&sealer)).unwrap(),
        );
        let c = Collector::with_store_and_forward(queue);
        let replayed = c.drain_spooled();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].node_id, "survivor");
    }
}
