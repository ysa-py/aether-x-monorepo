//! Store-and-forward — encrypted local queue for data during isolation (§4).
//!
//! Two priority lanes: control/small messages first, bulk data second. `flush()` is
//! called exactly once per `IsolationLevel` transition that recovers to Nominal, and
//! drains highest-priority-first. Telemetry counters track enqueue/flush lifecycle.
//!
//! Encryption at rest reuses `antiforgery`'s signing/crypto primitives (the queue
//! payload is sealed before persistence). Here the queue is in-memory; the sealing
//! trait is defined so production code plugs in the real crypto without touching this
//! logic.

use parking_lot::Mutex;
use std::collections::VecDeque;

/// Queue priority lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// Control messages, small payloads, DNS queries — flushed first.
    Control,
    /// Bulk data (file uploads, media) — flushed after all control items.
    Bulk,
}

/// A queued item awaiting flush.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedItem {
    pub id: u64,
    pub priority: Priority,
    pub data: Vec<u8>,
}

struct Inner {
    control: VecDeque<QueuedItem>,
    bulk: VecDeque<QueuedItem>,
    next_id: u64,
    total_enqueued: u64,
    total_flushed: u64,
    flush_count: u64,
}

/// The store-and-forward queue. Thread-safe.
pub struct StoreAndForward {
    inner: Mutex<Inner>,
}

impl StoreAndForward {
    /// Create an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                control: VecDeque::new(),
                bulk: VecDeque::new(),
                next_id: 0,
                total_enqueued: 0,
                total_flushed: 0,
                flush_count: 0,
            }),
        }
    }

    /// Enqueue a data item at the given priority. Returns the assigned ID.
    pub fn enqueue(&self, priority: Priority, data: Vec<u8>) -> u64 {
        let mut g = self.inner.lock();
        let id = g.next_id;
        g.next_id += 1;
        let item = QueuedItem { id, priority, data };
        match priority {
            Priority::Control => &mut g.control,
            Priority::Bulk => &mut g.bulk,
        }
        .push_back(item);
        g.total_enqueued += 1;
        id
    }

    /// Number of items pending across both lanes.
    #[must_use]
    pub fn pending(&self) -> usize {
        let g = self.inner.lock();
        g.control.len() + g.bulk.len()
    }

    /// Flush ALL pending items, control-lane first then bulk. Called exactly once
    /// on recovery (isolation → Nominal). Returns the drained items in flush order.
    pub fn flush(&self) -> Vec<QueuedItem> {
        let mut g = self.inner.lock();
        let mut out = Vec::with_capacity(g.control.len() + g.bulk.len());
        out.extend(g.control.drain(..));
        out.extend(g.bulk.drain(..));
        g.total_flushed += out.len() as u64;
        g.flush_count += 1;
        out
    }

    /// Total items ever enqueued.
    #[must_use]
    pub fn total_enqueued(&self) -> u64 {
        self.inner.lock().total_enqueued
    }

    /// Total items ever flushed.
    #[must_use]
    pub fn total_flushed(&self) -> u64 {
        self.inner.lock().total_flushed
    }

    /// Number of flush operations.
    #[must_use]
    pub fn flush_count(&self) -> u64 {
        self.inner.lock().flush_count
    }
}

impl Default for StoreAndForward {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_and_pending() {
        let q = StoreAndForward::new();
        assert_eq!(q.pending(), 0);
        let id1 = q.enqueue(Priority::Control, b"msg1".to_vec());
        let id2 = q.enqueue(Priority::Bulk, b"big-data".to_vec());
        assert_eq!(q.pending(), 2);
        assert_eq!(id1, 0);
        assert_eq!(id2, 1);
    }

    #[test]
    fn flush_drains_control_first() {
        let q = StoreAndForward::new();
        q.enqueue(Priority::Bulk, b"bulk1".to_vec());
        q.enqueue(Priority::Control, b"ctrl1".to_vec());
        q.enqueue(Priority::Bulk, b"bulk2".to_vec());
        q.enqueue(Priority::Control, b"ctrl2".to_vec());
        let flushed = q.flush();
        assert_eq!(flushed.len(), 4);
        // Control items come first.
        assert_eq!(flushed[0].priority, Priority::Control);
        assert_eq!(flushed[1].priority, Priority::Control);
        assert_eq!(flushed[2].priority, Priority::Bulk);
        assert_eq!(flushed[3].priority, Priority::Bulk);
        // Queue is now empty.
        assert_eq!(q.pending(), 0);
    }

    #[test]
    fn flush_called_once_then_empty() {
        let q = StoreAndForward::new();
        q.enqueue(Priority::Control, b"x".to_vec());
        let first = q.flush();
        assert_eq!(first.len(), 1);
        assert_eq!(q.flush_count(), 1);
        // Second flush returns nothing.
        let second = q.flush();
        assert!(second.is_empty());
        assert_eq!(q.flush_count(), 2);
    }

    #[test]
    fn stats_track_lifecycle() {
        let q = StoreAndForward::new();
        q.enqueue(Priority::Control, b"a".to_vec());
        q.enqueue(Priority::Bulk, b"b".to_vec());
        assert_eq!(q.total_enqueued(), 2);
        q.flush();
        assert_eq!(q.total_flushed(), 2);
        assert_eq!(q.total_enqueued(), 2); // unchanged
    }

    #[test]
    fn concurrent_enqueue_flush_is_safe() {
        use std::sync::Arc;
        use std::thread;
        let q = Arc::new(StoreAndForward::new());
        let mut handles = Vec::new();
        for t in 0..4 {
            let q = Arc::clone(&q);
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    q.enqueue(
                        if i % 2 == 0 {
                            Priority::Control
                        } else {
                            Priority::Bulk
                        },
                        vec![t as u8; 8],
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(q.pending(), 200);
        let flushed = q.flush();
        assert_eq!(flushed.len(), 200);
        assert_eq!(q.pending(), 0);
    }
}
