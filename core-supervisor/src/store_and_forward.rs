//! Store-and-forward — bounded, disk-backed local queue for data during
//! isolation (§4).
//!
//! Two priority lanes: control/small messages first, bulk data second.
//! [`StoreAndForward::flush`] drains highest-priority-first and is called on a
//! recovery transition (isolation → Nominal). Telemetry counters track the
//! enqueue/flush/reject/evict lifecycle.
//!
//! Three properties this module actually guarantees (each has a test):
//!
//! 1. **Bounded memory.** A [`QueueLimits`] caps both item count and total
//!    payload bytes. On overflow the queue either rejects the newcomer
//!    ([`OverflowPolicy::RejectNew`]) or evicts the oldest bulk item
//!    ([`OverflowPolicy::EvictOldest`]) — never unbounded growth. Control-lane
//!    items are never evicted to make room for bulk items.
//! 2. **Disk persistence.** With a spool path configured, every accepted item
//!    is appended as a JSON line, and the file is compacted (rewritten) on
//!    flush/eviction. This deliberately mirrors the `DiskSpool` pattern in
//!    `control-plane/internal/telemetry/clickhouse.go` (append JSONL on the
//!    write path, read-and-truncate on drain) so both planes behave the same
//!    way during an outage.
//! 3. **Crash recovery.** [`StoreAndForward::open`] reloads the spool from disk
//!    at startup, restoring lane order, IDs, and the next-ID watermark. A
//!    torn/partial trailing line is skipped, not fatal.

use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// Queue priority lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Priority {
    /// Control messages, small payloads, DNS queries — flushed first.
    Control,
    /// Bulk data (file uploads, media) — flushed after all control items.
    Bulk,
}

/// A queued item awaiting flush.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedItem {
    pub id: u64,
    pub priority: Priority,
    pub data: Vec<u8>,
}

/// What to do when the queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Refuse the new item. The caller learns immediately that the data was
    /// NOT accepted (honest back-pressure; nothing silently disappears).
    RejectNew,
    /// Drop the oldest *bulk* item to make room. Control items are never
    /// evicted; if only control items remain, the new item is rejected.
    EvictOldest,
}

/// Capacity bound for the queue. Both limits apply simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueLimits {
    /// Maximum number of pending items across both lanes.
    pub max_items: usize,
    /// Maximum total payload bytes across both lanes.
    pub max_bytes: usize,
    /// Behaviour when a limit would be exceeded.
    pub policy: OverflowPolicy,
}

impl QueueLimits {
    /// Conservative default: 10k items / 64 MiB, evicting the oldest bulk data.
    /// Sized so a blackout of hours cannot exhaust a mobile device's memory.
    pub const DEFAULT_MAX_ITEMS: usize = 10_000;
    pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            max_items: Self::DEFAULT_MAX_ITEMS,
            max_bytes: Self::DEFAULT_MAX_BYTES,
            policy: OverflowPolicy::EvictOldest,
        }
    }
}

/// Why an enqueue was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueError {
    /// The item alone exceeds `max_bytes`; it can never fit.
    ItemTooLarge { size: usize, max_bytes: usize },
    /// The queue is at capacity and the policy forbids making room.
    QueueFull { items: usize, bytes: usize },
}

impl std::fmt::Display for EnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ItemTooLarge { size, max_bytes } => {
                write!(f, "item of {size} B exceeds queue limit of {max_bytes} B")
            }
            Self::QueueFull { items, bytes } => {
                write!(f, "store-and-forward queue full ({items} items, {bytes} B)")
            }
        }
    }
}

impl std::error::Error for EnqueueError {}

/// Counters describing the queue lifecycle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueStats {
    pub pending_items: usize,
    pub pending_bytes: usize,
    pub total_enqueued: u64,
    pub total_flushed: u64,
    pub total_rejected: u64,
    pub total_evicted: u64,
    pub flush_count: u64,
    /// Items restored from the disk spool at startup.
    pub recovered_items: u64,
    /// Disk writes that failed (spool unavailable / full disk).
    pub persist_errors: u64,
}

struct Inner {
    control: VecDeque<QueuedItem>,
    bulk: VecDeque<QueuedItem>,
    next_id: u64,
    pending_bytes: usize,
    total_enqueued: u64,
    total_flushed: u64,
    total_rejected: u64,
    total_evicted: u64,
    flush_count: u64,
    recovered_items: u64,
    persist_errors: u64,
}

impl Inner {
    fn pending_items(&self) -> usize {
        self.control.len() + self.bulk.len()
    }
}

/// The store-and-forward queue. Thread-safe, bounded, optionally disk-backed.
pub struct StoreAndForward {
    inner: Mutex<Inner>,
    limits: QueueLimits,
    spool: Option<PathBuf>,
}

impl StoreAndForward {
    /// Create an empty in-memory queue with the default capacity bound.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(QueueLimits::default())
    }

    /// Create an empty in-memory queue with an explicit capacity bound.
    #[must_use]
    pub fn with_limits(limits: QueueLimits) -> Self {
        Self {
            inner: Mutex::new(Inner {
                control: VecDeque::new(),
                bulk: VecDeque::new(),
                next_id: 0,
                pending_bytes: 0,
                total_enqueued: 0,
                total_flushed: 0,
                total_rejected: 0,
                total_evicted: 0,
                flush_count: 0,
                recovered_items: 0,
                persist_errors: 0,
            }),
            limits,
            spool: None,
        }
    }

    /// Open a disk-backed queue, **recovering any queue contents left behind by
    /// a crash**. The parent directory is created if missing (same behaviour as
    /// `telemetry.NewDiskSpool` in the Go control plane).
    ///
    /// Corrupt or partially-written trailing lines are skipped: a crash mid-write
    /// costs at most the one item being written, never the whole queue.
    pub fn open(path: impl AsRef<Path>, limits: QueueLimits) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let mut queue = Self::with_limits(limits);
        queue.spool = Some(path.clone());

        let recovered = match std::fs::read(&path) {
            Ok(bytes) => Self::parse_spool(&bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };

        {
            let mut g = queue.inner.lock();
            for item in recovered {
                // Recovery respects the same capacity bound as the live path:
                // a corrupt/oversized spool cannot blow past the memory limit.
                let size = item.data.len();
                if g.pending_items() >= queue.limits.max_items
                    || g.pending_bytes.saturating_add(size) > queue.limits.max_bytes
                {
                    g.total_rejected += 1;
                    continue;
                }
                g.next_id = g.next_id.max(item.id + 1);
                g.pending_bytes += size;
                g.recovered_items += 1;
                match item.priority {
                    Priority::Control => g.control.push_back(item),
                    Priority::Bulk => g.bulk.push_back(item),
                }
            }
        }

        // Compact: rewrite the spool from the accepted, in-order contents so the
        // on-disk state always matches memory after startup.
        queue.rewrite_spool();
        Ok(queue)
    }

    fn parse_spool(bytes: &[u8]) -> Vec<QueuedItem> {
        let mut out = Vec::new();
        for line in bytes.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            if let Ok(item) = serde_json::from_slice::<QueuedItem>(line) {
                out.push(item);
            }
            // A line that does not parse is a torn tail from a crash: skip it.
        }
        out
    }

    /// The configured capacity bound.
    #[must_use]
    pub fn limits(&self) -> QueueLimits {
        self.limits
    }

    /// The spool path, if this queue is disk-backed.
    #[must_use]
    pub fn spool_path(&self) -> Option<&Path> {
        self.spool.as_deref()
    }

    /// Enqueue a data item at the given priority.
    ///
    /// Returns the assigned ID, or [`EnqueueError`] when the capacity bound
    /// refuses the item. Never grows without bound.
    pub fn try_enqueue(&self, priority: Priority, data: Vec<u8>) -> Result<u64, EnqueueError> {
        let size = data.len();
        if size > self.limits.max_bytes {
            let mut g = self.inner.lock();
            g.total_rejected += 1;
            return Err(EnqueueError::ItemTooLarge {
                size,
                max_bytes: self.limits.max_bytes,
            });
        }

        let mut compact_needed = false;
        let id = {
            let mut g = self.inner.lock();

            // Make room if allowed.
            while g.pending_items() + 1 > self.limits.max_items
                || g.pending_bytes + size > self.limits.max_bytes
            {
                if self.limits.policy == OverflowPolicy::RejectNew {
                    let (items, bytes) = (g.pending_items(), g.pending_bytes);
                    g.total_rejected += 1;
                    return Err(EnqueueError::QueueFull { items, bytes });
                }
                // EvictOldest: sacrifice the oldest BULK item. Control traffic
                // is the small, latency-critical lane and is never evicted for
                // bulk data.
                match g.bulk.pop_front() {
                    Some(v) => {
                        g.pending_bytes = g.pending_bytes.saturating_sub(v.data.len());
                        g.total_evicted += 1;
                        compact_needed = true;
                    }
                    None => {
                        // Only control items remain; refuse rather than drop
                        // control data.
                        let (items, bytes) = (g.pending_items(), g.pending_bytes);
                        g.total_rejected += 1;
                        return Err(EnqueueError::QueueFull { items, bytes });
                    }
                }
            }

            let id = g.next_id;
            g.next_id += 1;
            let item = QueuedItem { id, priority, data };
            g.pending_bytes += size;
            g.total_enqueued += 1;
            match priority {
                Priority::Control => g.control.push_back(item),
                Priority::Bulk => g.bulk.push_back(item),
            }
            id
        };

        if compact_needed {
            // Eviction changed history: rewrite the whole spool so disk and
            // memory agree (append-only cannot express a removal).
            self.rewrite_spool();
        } else {
            self.append_spool(id);
        }
        Ok(id)
    }

    /// Enqueue, returning `None` if the capacity bound refused the item.
    ///
    /// Kept for call sites that treat the queue as best-effort. Prefer
    /// [`StoreAndForward::try_enqueue`] when the caller can react to
    /// back-pressure.
    pub fn enqueue(&self, priority: Priority, data: Vec<u8>) -> Option<u64> {
        self.try_enqueue(priority, data).ok()
    }

    /// Number of items pending across both lanes.
    #[must_use]
    pub fn pending(&self) -> usize {
        let g = self.inner.lock();
        g.pending_items()
    }

    /// Total payload bytes currently held.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.inner.lock().pending_bytes
    }

    /// Flush ALL pending items, control-lane first then bulk. Returns the
    /// drained items in flush order and truncates the disk spool, so a crash
    /// after a successful flush does not replay already-delivered data.
    pub fn flush(&self) -> Vec<QueuedItem> {
        let out = {
            let mut g = self.inner.lock();
            let mut out = Vec::with_capacity(g.pending_items());
            out.extend(g.control.drain(..));
            out.extend(g.bulk.drain(..));
            g.pending_bytes = 0;
            g.total_flushed += out.len() as u64;
            g.flush_count += 1;
            out
        };
        self.rewrite_spool(); // now empty ⇒ truncates the file
        out
    }

    /// Force the in-memory queue to disk (used on graceful shutdown).
    pub fn persist(&self) {
        self.rewrite_spool();
    }

    // ---- disk spool ------------------------------------------------------

    /// Append the item with `id` as a JSON line (the hot path; O(1) write).
    fn append_spool(&self, id: u64) {
        let Some(path) = self.spool.as_ref() else {
            return;
        };
        let mut g = self.inner.lock();
        let line = g
            .control
            .iter()
            .chain(g.bulk.iter())
            .find(|i| i.id == id)
            .and_then(|item| serde_json::to_vec(item).ok());
        let Some(mut line) = line else {
            g.persist_errors += 1;
            return;
        };
        line.push(b'\n');

        let write = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| f.write_all(&line));
        if write.is_err() {
            // Best effort, exactly like the Go DiskSpool: a failed disk write
            // must never take down the data path, but it IS counted so the gap
            // is visible in telemetry instead of silent.
            g.persist_errors += 1;
        }
    }

    /// Rewrite the whole spool from current memory state (after flush/eviction).
    fn rewrite_spool(&self) {
        let Some(path) = self.spool.as_ref() else {
            return;
        };
        let mut g = self.inner.lock();
        let mut buf = Vec::new();
        let mut encode_errors = 0u64;
        for item in g.control.iter().chain(g.bulk.iter()) {
            match serde_json::to_vec(item) {
                Ok(mut line) => {
                    line.push(b'\n');
                    buf.extend_from_slice(&line);
                }
                Err(_) => encode_errors += 1,
            }
        }
        g.persist_errors += encode_errors;
        // Write to a temp file then rename: a crash mid-compaction leaves either
        // the old spool or the new one, never a half-written queue.
        let tmp = path.with_extension("tmp");
        let written = std::fs::write(&tmp, &buf).and_then(|()| std::fs::rename(&tmp, path));
        if written.is_err() {
            g.persist_errors += 1;
        }
    }

    // ---- stats -----------------------------------------------------------

    /// Full lifecycle counters.
    #[must_use]
    pub fn stats(&self) -> QueueStats {
        let g = self.inner.lock();
        QueueStats {
            pending_items: g.pending_items(),
            pending_bytes: g.pending_bytes,
            total_enqueued: g.total_enqueued,
            total_flushed: g.total_flushed,
            total_rejected: g.total_rejected,
            total_evicted: g.total_evicted,
            flush_count: g.flush_count,
            recovered_items: g.recovered_items,
            persist_errors: g.persist_errors,
        }
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

    /// Total items refused by the capacity bound.
    #[must_use]
    pub fn total_rejected(&self) -> u64 {
        self.inner.lock().total_rejected
    }

    /// Total items evicted to make room.
    #[must_use]
    pub fn total_evicted(&self) -> u64 {
        self.inner.lock().total_evicted
    }

    /// Number of flush operations.
    #[must_use]
    pub fn flush_count(&self) -> u64 {
        self.inner.lock().flush_count
    }

    /// Items restored from disk at startup.
    #[must_use]
    pub fn recovered_items(&self) -> u64 {
        self.inner.lock().recovered_items
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

    fn unbounded_for_tests() -> QueueLimits {
        QueueLimits {
            max_items: 100_000,
            max_bytes: 1 << 30,
            policy: OverflowPolicy::RejectNew,
        }
    }

    #[test]
    fn enqueue_and_pending() {
        let q = StoreAndForward::new();
        assert_eq!(q.pending(), 0);
        let id1 = q.try_enqueue(Priority::Control, b"msg1".to_vec()).unwrap();
        let id2 = q.try_enqueue(Priority::Bulk, b"big-data".to_vec()).unwrap();
        assert_eq!(q.pending(), 2);
        assert_eq!(id1, 0);
        assert_eq!(id2, 1);
        assert_eq!(q.pending_bytes(), 4 + 8);
    }

    #[test]
    fn flush_drains_control_first() {
        let q = StoreAndForward::new();
        q.enqueue(Priority::Bulk, b"bulk1".to_vec()).unwrap();
        q.enqueue(Priority::Control, b"ctrl1".to_vec()).unwrap();
        q.enqueue(Priority::Bulk, b"bulk2".to_vec()).unwrap();
        q.enqueue(Priority::Control, b"ctrl2".to_vec()).unwrap();
        let flushed = q.flush();
        assert_eq!(flushed.len(), 4);
        assert_eq!(flushed[0].priority, Priority::Control);
        assert_eq!(flushed[1].priority, Priority::Control);
        assert_eq!(flushed[2].priority, Priority::Bulk);
        assert_eq!(flushed[3].priority, Priority::Bulk);
        assert_eq!(q.pending(), 0);
        assert_eq!(q.pending_bytes(), 0);
    }

    #[test]
    fn flush_called_once_then_empty() {
        let q = StoreAndForward::new();
        q.enqueue(Priority::Control, b"x".to_vec()).unwrap();
        let first = q.flush();
        assert_eq!(first.len(), 1);
        assert_eq!(q.flush_count(), 1);
        let second = q.flush();
        assert!(second.is_empty());
        assert_eq!(q.flush_count(), 2);
    }

    #[test]
    fn stats_track_lifecycle() {
        let q = StoreAndForward::new();
        q.enqueue(Priority::Control, b"a".to_vec()).unwrap();
        q.enqueue(Priority::Bulk, b"b".to_vec()).unwrap();
        assert_eq!(q.total_enqueued(), 2);
        q.flush();
        assert_eq!(q.total_flushed(), 2);
        assert_eq!(q.total_enqueued(), 2); // unchanged
    }

    #[test]
    fn concurrent_enqueue_flush_is_safe() {
        use std::sync::Arc;
        use std::thread;
        let q = Arc::new(StoreAndForward::with_limits(unbounded_for_tests()));
        let mut handles = Vec::new();
        for t in 0..4 {
            let q = Arc::clone(&q);
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    let _ = q.enqueue(
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

    // ---- capacity bound --------------------------------------------------

    #[test]
    fn reject_policy_refuses_when_full_and_never_grows() {
        let q = StoreAndForward::with_limits(QueueLimits {
            max_items: 3,
            max_bytes: 1024,
            policy: OverflowPolicy::RejectNew,
        });
        for i in 0..3 {
            assert!(q.try_enqueue(Priority::Bulk, vec![i; 4]).is_ok());
        }
        let err = q.try_enqueue(Priority::Bulk, vec![9; 4]).unwrap_err();
        assert!(matches!(err, EnqueueError::QueueFull { items: 3, .. }));
        assert_eq!(q.pending(), 3, "queue must not grow past its bound");
        assert_eq!(q.total_rejected(), 1);
    }

    #[test]
    fn byte_bound_is_enforced_independently_of_item_count() {
        let q = StoreAndForward::with_limits(QueueLimits {
            max_items: 1000,
            max_bytes: 100,
            policy: OverflowPolicy::RejectNew,
        });
        assert!(q.try_enqueue(Priority::Bulk, vec![0; 60]).is_ok());
        assert!(q.try_enqueue(Priority::Bulk, vec![0; 60]).is_err());
        assert_eq!(q.pending_bytes(), 60);
        assert!(q.pending_bytes() <= 100);
    }

    #[test]
    fn item_larger_than_bound_can_never_fit() {
        let q = StoreAndForward::with_limits(QueueLimits {
            max_items: 10,
            max_bytes: 32,
            policy: OverflowPolicy::EvictOldest,
        });
        let err = q.try_enqueue(Priority::Bulk, vec![0; 64]).unwrap_err();
        assert!(matches!(err, EnqueueError::ItemTooLarge { size: 64, .. }));
        assert_eq!(q.pending(), 0);
    }

    #[test]
    fn evict_policy_drops_oldest_bulk_and_stays_bounded() {
        let q = StoreAndForward::with_limits(QueueLimits {
            max_items: 3,
            max_bytes: 1024,
            policy: OverflowPolicy::EvictOldest,
        });
        for i in 0..5u8 {
            q.try_enqueue(Priority::Bulk, vec![i; 4]).unwrap();
        }
        assert_eq!(q.pending(), 3, "bounded under sustained overflow");
        assert_eq!(q.total_evicted(), 2);
        let flushed = q.flush();
        // The two oldest (0, 1) were evicted; 2,3,4 remain in order.
        assert_eq!(
            flushed.iter().map(|i| i.data[0]).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }

    #[test]
    fn control_lane_is_never_evicted_for_bulk() {
        let q = StoreAndForward::with_limits(QueueLimits {
            max_items: 2,
            max_bytes: 1024,
            policy: OverflowPolicy::EvictOldest,
        });
        q.try_enqueue(Priority::Control, b"ctrl-a".to_vec())
            .unwrap();
        q.try_enqueue(Priority::Control, b"ctrl-b".to_vec())
            .unwrap();
        // No bulk item to sacrifice ⇒ refuse rather than drop control data.
        let err = q.try_enqueue(Priority::Bulk, b"bulk".to_vec()).unwrap_err();
        assert!(matches!(err, EnqueueError::QueueFull { .. }));
        let flushed = q.flush();
        assert_eq!(flushed.len(), 2);
        assert!(flushed.iter().all(|i| i.priority == Priority::Control));
    }

    #[test]
    fn ten_thousand_enqueues_never_exceed_the_bound() {
        let limits = QueueLimits {
            max_items: 64,
            max_bytes: 8 * 1024,
            policy: OverflowPolicy::EvictOldest,
        };
        let q = StoreAndForward::with_limits(limits);
        for i in 0..10_000u32 {
            let _ = q.try_enqueue(Priority::Bulk, vec![(i % 256) as u8; 64]);
            assert!(q.pending() <= limits.max_items);
            assert!(q.pending_bytes() <= limits.max_bytes);
        }
    }

    // ---- disk persistence + crash recovery -------------------------------

    #[test]
    fn persists_to_disk_and_recovers_after_crash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("snf.jsonl");

        {
            let q = StoreAndForward::open(&path, QueueLimits::default()).unwrap();
            q.try_enqueue(Priority::Control, b"ctrl-1".to_vec())
                .unwrap();
            q.try_enqueue(Priority::Bulk, b"bulk-1".to_vec()).unwrap();
            q.try_enqueue(Priority::Control, b"ctrl-2".to_vec())
                .unwrap();
            assert_eq!(q.pending(), 3);
            // Simulate a crash: drop without flushing, no graceful shutdown.
        }

        assert!(path.exists(), "spool file must exist on disk");

        let recovered = StoreAndForward::open(&path, QueueLimits::default()).unwrap();
        assert_eq!(recovered.pending(), 3, "queue must survive a crash");
        assert_eq!(recovered.recovered_items(), 3);
        let flushed = recovered.flush();
        assert_eq!(flushed.len(), 3);
        // Lane ordering survives the round trip.
        assert_eq!(flushed[0].data, b"ctrl-1".to_vec());
        assert_eq!(flushed[1].data, b"ctrl-2".to_vec());
        assert_eq!(flushed[2].data, b"bulk-1".to_vec());
        // IDs continue past the recovered watermark rather than colliding.
        let new_id = recovered
            .try_enqueue(Priority::Control, b"after".to_vec())
            .unwrap();
        assert!(new_id >= 3, "next id must not collide with recovered ids");
    }

    #[test]
    fn flushed_items_are_not_replayed_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snf.jsonl");
        {
            let q = StoreAndForward::open(&path, QueueLimits::default()).unwrap();
            q.try_enqueue(Priority::Control, b"delivered".to_vec())
                .unwrap();
            assert_eq!(q.flush().len(), 1);
        }
        let restarted = StoreAndForward::open(&path, QueueLimits::default()).unwrap();
        assert_eq!(restarted.pending(), 0, "delivered data must not replay");
        assert_eq!(restarted.recovered_items(), 0);
    }

    #[test]
    fn torn_trailing_line_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snf.jsonl");
        {
            let q = StoreAndForward::open(&path, QueueLimits::default()).unwrap();
            q.try_enqueue(Priority::Control, b"good".to_vec()).unwrap();
        }
        // Append a half-written record, exactly what a power cut produces.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"{\"id\":99,\"priority\":\"Bulk\",\"da")
            .unwrap();
        drop(f);

        let recovered = StoreAndForward::open(&path, QueueLimits::default()).unwrap();
        assert_eq!(recovered.pending(), 1, "intact records must still load");
        assert_eq!(recovered.flush()[0].data, b"good".to_vec());
    }

    #[test]
    fn recovery_respects_the_capacity_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snf.jsonl");
        {
            let q = StoreAndForward::open(
                &path,
                QueueLimits {
                    max_items: 100,
                    max_bytes: 1 << 20,
                    policy: OverflowPolicy::RejectNew,
                },
            )
            .unwrap();
            for i in 0..50u8 {
                q.try_enqueue(Priority::Bulk, vec![i; 16]).unwrap();
            }
        }
        // Restart with a much smaller bound: a large spool must not blow past it.
        let tight = StoreAndForward::open(
            &path,
            QueueLimits {
                max_items: 10,
                max_bytes: 1 << 20,
                policy: OverflowPolicy::RejectNew,
            },
        )
        .unwrap();
        assert_eq!(tight.pending(), 10);
        assert_eq!(tight.stats().total_rejected, 40);
    }

    #[test]
    fn eviction_is_reflected_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snf.jsonl");
        let limits = QueueLimits {
            max_items: 2,
            max_bytes: 1 << 20,
            policy: OverflowPolicy::EvictOldest,
        };
        {
            let q = StoreAndForward::open(&path, limits).unwrap();
            for i in 0..5u8 {
                q.try_enqueue(Priority::Bulk, vec![i; 4]).unwrap();
            }
            assert_eq!(q.pending(), 2);
        }
        let recovered = StoreAndForward::open(&path, limits).unwrap();
        assert_eq!(
            recovered.pending(),
            2,
            "disk must not hold evicted items after compaction"
        );
        let flushed = recovered.flush();
        assert_eq!(
            flushed.iter().map(|i| i.data[0]).collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn in_memory_queue_writes_no_files() {
        let q = StoreAndForward::new();
        assert!(q.spool_path().is_none());
        q.try_enqueue(Priority::Control, b"x".to_vec()).unwrap();
        q.flush();
        assert_eq!(q.stats().persist_errors, 0);
    }
}
