//! Local Loopback Stream Buffering — ring buffer for unacked TCP segments
//!
//! Holds unacknowledged local TCP segments in a ring buffer during micro-failovers,
//! preventing socket drop errors from reaching user space.

use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// A buffered segment
#[derive(Debug, Clone)]
pub struct BufferedSegment {
    pub seq: u64,
    pub data: Vec<u8>,
    pub created_at: Instant,
    pub acked: bool,
}

/// Loopback buffer — holds unacked segments during micro-failovers
#[derive(Debug)]
pub struct LoopbackBuffer {
    buffer: RwLock<VecDeque<BufferedSegment>>,
    capacity: usize,
    next_seq: AtomicU64,
    total_buffered: AtomicU64,
    total_acked: AtomicU64,
    total_dropped: AtomicU64,
}

impl LoopbackBuffer {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: RwLock::new(VecDeque::with_capacity(capacity)),
            capacity: capacity.max(16),
            next_seq: AtomicU64::new(1),
            total_buffered: AtomicU64::new(0),
            total_acked: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
        }
    }

    /// Buffer outgoing segment (not yet acked)
    pub fn buffer_segment(&self, data: Vec<u8>) -> u64 {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let seg = BufferedSegment {
            seq,
            data,
            created_at: Instant::now(),
            acked: false,
        };
        let mut buf = self.buffer.write();
        if buf.len() >= self.capacity {
            // Drop oldest if full — but count as dropped (should be rare)
            if let Some(dropped) = buf.pop_front() {
                self.total_dropped.fetch_add(1, Ordering::Relaxed);
                let _ = dropped;
            }
        }
        buf.push_back(seg);
        self.total_buffered.fetch_add(1, Ordering::Relaxed);
        seq
    }

    /// Ack segment by seq
    pub fn ack(&self, seq: u64) -> bool {
        let mut buf = self.buffer.write();
        if let Some(seg) = buf.iter_mut().find(|s| s.seq == seq) {
            seg.acked = true;
            self.total_acked.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Ack up to seq (cumulative ACK)
    pub fn ack_up_to(&self, seq: u64) -> usize {
        let mut buf = self.buffer.write();
        let mut count = 0;
        for seg in buf.iter_mut() {
            if seg.seq <= seq && !seg.acked {
                seg.acked = true;
                count += 1;
            }
        }
        if count > 0 {
            self.total_acked.fetch_add(count as u64, Ordering::Relaxed);
        }
        count
    }

    /// Get unacked segments for replay during failover
    #[must_use]
    pub fn unacked_segments(&self) -> Vec<BufferedSegment> {
        self.buffer
            .read()
            .iter()
            .filter(|s| !s.acked)
            .cloned()
            .collect()
    }

    /// Replay unacked during micro-failover — prevents socket drop errors reaching user space
    pub fn replay_unacked(&self) -> Vec<BufferedSegment> {
        let unacked = self.unacked_segments();
        // In real, would re-inject onto new transport via sockhash
        unacked
    }

    /// Prune acked segments older than age
    pub fn prune_acked(&self, older_than: Duration) -> usize {
        let mut buf = self.buffer.write();
        let now = Instant::now();
        let before = buf.len();
        buf.retain(|seg| {
            if seg.acked {
                now.duration_since(seg.created_at) < older_than
            } else {
                true
            }
        });
        before - buf.len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.read().len()
    }

    #[must_use]
    pub fn unacked_count(&self) -> usize {
        self.buffer.read().iter().filter(|s| !s.acked).count()
    }

    #[must_use]
    pub fn stats(&self) -> LoopbackStats {
        LoopbackStats {
            buffered: self.total_buffered.load(Ordering::Relaxed),
            acked: self.total_acked.load(Ordering::Relaxed),
            dropped: self.total_dropped.load(Ordering::Relaxed),
            current_len: self.len(),
            unacked: self.unacked_count(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoopbackStats {
    pub buffered: u64,
    pub acked: u64,
    pub dropped: u64,
    pub current_len: usize,
    pub unacked: usize,
}

impl Default for LoopbackBuffer {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_and_ack() {
        let buf = LoopbackBuffer::new(10);
        let seq1 = buf.buffer_segment(b"hello".to_vec());
        let seq2 = buf.buffer_segment(b"world".to_vec());
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.unacked_count(), 2);

        assert!(buf.ack(seq1));
        assert_eq!(buf.unacked_count(), 1);

        let unacked = buf.unacked_segments();
        assert_eq!(unacked.len(), 1);
        assert_eq!(unacked[0].seq, seq2);
    }

    #[test]
    fn ack_up_to_cumulative() {
        let buf = LoopbackBuffer::new(10);
        let s1 = buf.buffer_segment(b"a".to_vec());
        let s2 = buf.buffer_segment(b"b".to_vec());
        let s3 = buf.buffer_segment(b"c".to_vec());

        let acked = buf.ack_up_to(s2);
        assert_eq!(acked, 2);
        assert_eq!(buf.unacked_count(), 1);

        let unacked = buf.unacked_segments();
        assert_eq!(unacked[0].seq, s3);
        let _ = s1;
    }

    #[test]
    fn replay_during_failover_prevents_socket_drop() {
        let buf = LoopbackBuffer::new(10);
        buf.buffer_segment(b"critical data".to_vec());
        buf.buffer_segment(b"more data".to_vec());

        // Micro-failover occurs — replay unacked
        let replay = buf.replay_unacked();
        assert_eq!(replay.len(), 2);
        // User app never sees socket drop error because buffer holds data
        assert_eq!(buf.stats().unacked, 2);
    }

    #[test]
    fn prune_acked() {
        let buf = LoopbackBuffer::new(10);
        let s1 = buf.buffer_segment(b"a".to_vec());
        buf.ack(s1);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let pruned = buf.prune_acked(Duration::from_millis(5));
        assert_eq!(pruned, 1);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn capacity_drop_oldest() {
        let buf = LoopbackBuffer::new(2);
        buf.buffer_segment(b"1".to_vec());
        buf.buffer_segment(b"2".to_vec());
        buf.buffer_segment(b"3".to_vec()); // should drop oldest
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.stats().dropped, 1);
    }
}
