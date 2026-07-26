//! Zero-disconnection buffer replay.
//!
//! The single biggest source of *user-perceived* disconnect during a transport
//! swap is not the swap itself — the [`crate::failover::FailoverBridge`] does
//! that in < 1 ms. It is the **in-flight frames that vanish**: TCP/QUIC data
//! already handed to the dying transport but not yet acknowledged by the peer.
//! When that transport dies, those frames are lost, the peer sees a gap, and
//! the upper layer stalls/retransmits on its own timer — that stall *is* the
//! disconnect the user feels.
//!
//! [`RingBufferReplay`] closes that gap. Every frame handed to a transport is
//! also held here until acknowledged. On a transport drop or a loss spike
//! (> 15 %), the buffered frames are **re-injected onto the winning path**
//! chosen by [`crate::multipath::MultipathRacer`] before the peer can notice
//! the gap — sub-millisecond, no socket teardown, no user-visible stall.
//!
//! Memory-bounded (a fixed-capacity ring): if it ever fills, the oldest
//! unacked frame is dropped and counted, so a misbehaving peer cannot grow
//! memory unbounded. Thread-safe under a mutex; safe Rust only.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::time::Instant;

/// Loss rate at/above which a replay is triggered (spec: > 15 %).
pub const LOSS_SPIKE_THRESHOLD: f64 = 0.15;

/// An in-flight, not-yet-acknowledged frame held for potential replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Monotonic sequence number (assigned on `push`).
    pub seq: u64,
    /// Raw frame payload (TCP segment / QUIC frame bytes).
    pub data: Vec<u8>,
    /// When the frame was first handed to a transport.
    pub sent_at: Instant,
    /// How many times this frame has been re-injected onto a new path.
    pub hops: u32,
}

struct Inner {
    frames: VecDeque<Frame>,
    capacity: usize,
    next_seq: u64,
    replay_count: u64,
    dropped_count: u64,
    /// Hard cap on re-injection attempts per frame (prevents infinite replay
    /// of a frame the peer will never ack).
    max_hops: u32,
}

/// Bounded ring buffer of unacknowledged in-flight frames with replay.
pub struct RingBufferReplay {
    inner: Mutex<Inner>,
}

impl RingBufferReplay {
    /// Create a replay buffer holding up to `capacity` unacked frames.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_max_hops(capacity, 8)
    }

    /// Create with an explicit per-frame re-injection cap.
    #[must_use]
    pub fn with_max_hops(capacity: usize, max_hops: u32) -> Self {
        Self {
            inner: Mutex::new(Inner {
                frames: VecDeque::with_capacity(capacity.max(1)),
                capacity: capacity.max(1),
                next_seq: 0,
                replay_count: 0,
                dropped_count: 0,
                max_hops,
            }),
        }
    }

    /// Buffer a frame for a transport send. Returns the assigned sequence.
    /// If the ring is full, the oldest unacked frame is evicted (and counted).
    pub fn push(&self, data: Vec<u8>) -> u64 {
        let mut g = self.inner.lock();
        if g.frames.len() >= g.capacity {
            g.frames.pop_front();
            g.dropped_count += 1;
        }
        let seq = g.next_seq;
        g.next_seq += 1;
        g.frames.push_back(Frame {
            seq,
            data,
            sent_at: Instant::now(),
            hops: 0,
        });
        seq
    }

    /// Acknowledge every frame with `seq <= upto_seq` (the peer received them).
    /// Returns how many frames were retired.
    pub fn ack(&self, upto_seq: u64) -> usize {
        let mut g = self.inner.lock();
        let before = g.frames.len();
        g.frames.retain(|f| f.seq > upto_seq);
        before - g.frames.len()
    }

    /// Number of unacknowledged frames currently buffered.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.inner.lock().frames.len()
    }

    /// Clone every still-unacked frame for re-injection, bumping each frame's
    /// hop count (frames that have exceeded `max_hops` are retired instead of
    /// being replayed forever). This is the "replay onto the winning path"
    /// path — call it on a transport drop.
    pub fn replay_all(&self) -> Vec<Frame> {
        let mut g = self.inner.lock();
        let max_hops = g.max_hops;
        // Retire frames that have already been replayed too many times.
        g.frames.retain(|f| f.hops < max_hops);
        for f in &mut g.frames {
            f.hops += 1;
        }
        g.replay_count += 1;
        g.frames.iter().cloned().collect()
    }

    /// React to a measured loss rate. If it exceeds the spike threshold, return
    /// the frames to re-inject; otherwise `None` (no action).
    pub fn on_loss_spike(&self, loss_rate: f64) -> Option<Vec<Frame>> {
        if loss_rate > LOSS_SPIKE_THRESHOLD {
            Some(self.replay_all())
        } else {
            None
        }
    }

    /// React to a hard transport drop: always replay every unacked frame.
    pub fn on_drop(&self) -> Vec<Frame> {
        self.replay_all()
    }

    /// Total replay events triggered.
    #[must_use]
    pub fn replay_count(&self) -> u64 {
        self.inner.lock().replay_count
    }

    /// Frames evicted because the ring was full (memory-pressure signal).
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.inner.lock().dropped_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn push_ack_retires_in_order() {
        let rb = RingBufferReplay::new(16);
        rb.push(b"a".to_vec());
        let s1 = rb.push(b"b".to_vec());
        let s2 = rb.push(b"c".to_vec());
        assert_eq!(rb.pending(), 3);
        // Ack up to s1 → a, b retired; c remains.
        assert_eq!(rb.ack(s1), 2);
        assert_eq!(rb.pending(), 1);
        assert_eq!(rb.ack(s2), 1);
        assert_eq!(rb.pending(), 0);
    }

    #[test]
    fn replay_returns_unacked_frames_and_bumps_hops() {
        let rb = RingBufferReplay::new(16);
        rb.push(b"hello".to_vec());
        rb.push(b"world".to_vec());
        let replayed = rb.on_drop();
        assert_eq!(replayed.len(), 2);
        // Each frame's hop count incremented to 1.
        assert!(replayed.iter().all(|f| f.hops == 1));
        assert_eq!(rb.replay_count(), 1);
        // Frames are still buffered (unacked) — pending unchanged.
        assert_eq!(rb.pending(), 2);
        // Re-injected frames carry their original payload.
        assert_eq!(replayed[0].data, b"hello");
    }

    #[test]
    fn loss_spike_threshold_controls_replay() {
        let rb = RingBufferReplay::new(16);
        rb.push(b"x".to_vec());
        // 15 % exactly → not a spike (strictly greater-than).
        assert!(rb.on_loss_spike(0.15).is_none());
        // 16 % → spike → replay.
        let r = rb.on_loss_spike(0.16).expect("spike replays");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn ring_evicts_oldest_when_full_and_counts() {
        let rb = RingBufferReplay::new(2);
        rb.push(b"1".to_vec());
        rb.push(b"2".to_vec());
        assert_eq!(rb.pending(), 2);
        rb.push(b"3".to_vec()); // evicts "1"
        assert_eq!(rb.pending(), 2);
        assert_eq!(rb.dropped_count(), 1);
        // Oldest remaining is "2".
        let replayed = rb.on_drop();
        assert_eq!(replayed[0].data, b"2");
    }

    #[test]
    fn frames_beyond_max_hops_are_retired_not_replayed_forever() {
        let rb = RingBufferReplay::with_max_hops(8, 2);
        rb.push(b"stuck".to_vec());
        let _ = rb.on_drop(); // hops 0→1
        let _ = rb.on_drop(); // hops 1→2
                              // Third drop: frame at max_hops (2) is retired → nothing to replay.
        let third = rb.on_drop();
        assert!(third.is_empty(), "frame should be retired at max_hops");
        assert_eq!(rb.pending(), 0);
    }

    #[test]
    fn concurrent_push_ack_replay_is_race_free() {
        // Stress under -race equivalent: many threads push/ack/replay.
        let rb = Arc::new(RingBufferReplay::new(1024));
        let mut handles = Vec::new();
        for t in 0..8 {
            let rb = Arc::clone(&rb);
            handles.push(thread::spawn(move || {
                for i in 0..200 {
                    let seq = rb.push(vec![t as u8; 32]);
                    if i % 2 == 0 {
                        let _ = rb.ack(seq);
                    }
                    if i % 7 == 0 {
                        let _ = rb.on_drop();
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // No deadlock / panic; state is internally consistent.
        assert!(rb.pending() <= 1024);
    }
}
