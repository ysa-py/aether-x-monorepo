//! gRPC multiplexing transport fallback.
//!
//! When DPI allows gRPC (e.g. to whitelisted domains using gRPC), we
//! multiplex multiple logical streams over a single gRPC connection,
//! improving efficiency and resistance to RST injection.

use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// A multiplexed stream inside gRPC.
#[derive(Debug, Clone)]
pub struct GrpcStream {
    pub id: u64,
    pub created_at: Instant,
    pub bytes: u64,
    pub closed: bool,
}

/// gRPC multiplex transport.
#[derive(Debug)]
pub struct GrpcMuxTransport {
    pub endpoint: String, // whitelisted gRPC endpoint
    streams: RwLock<Vec<GrpcStream>>,
    next_id: AtomicU64,
    bytes_total: AtomicU64,
}

impl GrpcMuxTransport {
    #[must_use]
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            streams: RwLock::new(Vec::new()),
            next_id: AtomicU64::new(1),
            bytes_total: AtomicU64::new(0),
        }
    }

    /// Open a new multiplexed stream.
    pub fn open_stream(&self) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let stream = GrpcStream {
            id,
            created_at: Instant::now(),
            bytes: 0,
            closed: false,
        };
        {
            let mut streams = self.streams.write();
            streams.push(stream);
        }
        id
    }

    /// Write bytes to a stream.
    pub fn write_stream(&self, stream_id: u64, bytes: u64) -> bool {
        let mut streams = self.streams.write();
        if let Some(s) = streams.iter_mut().find(|s| s.id == stream_id && !s.closed) {
            s.bytes += bytes;
            self.bytes_total.fetch_add(bytes, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Close a stream.
    pub fn close_stream(&self, stream_id: u64) -> bool {
        let mut streams = self.streams.write();
        if let Some(s) = streams.iter_mut().find(|s| s.id == stream_id) {
            s.closed = true;
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn active_streams(&self) -> usize {
        self.streams.read().iter().filter(|s| !s.closed).count()
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.bytes_total.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn total_streams_opened(&self) -> u64 {
        self.next_id.load(Ordering::Relaxed) - 1
    }

    /// Simulate keepalive + window update (gRPC flow control).
    #[must_use]
    pub fn keepalive_needed(&self) -> bool {
        // If any stream >5s old and active, keepalive
        let now = Instant::now();
        self.streams
            .read()
            .iter()
            .any(|s| !s.closed && now.duration_since(s.created_at) > Duration::from_secs(5))
    }
}

impl Default for GrpcMuxTransport {
    fn default() -> Self {
        Self::new("www.digikala.com:443")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mux_streams() {
        let t = GrpcMuxTransport::new("www.aparat.com:443");
        let id1 = t.open_stream();
        let id2 = t.open_stream();
        assert_eq!(t.active_streams(), 2);
        assert!(t.write_stream(id1, 1024));
        assert!(t.write_stream(id2, 2048));
        assert_eq!(t.total_bytes(), 3072);
        assert!(t.close_stream(id1));
        assert_eq!(t.active_streams(), 1);
        assert_eq!(t.total_streams_opened(), 2);
    }

    #[test]
    fn write_closed_fails() {
        let t = GrpcMuxTransport::default();
        let id = t.open_stream();
        t.close_stream(id);
        assert!(!t.write_stream(id, 100));
    }

    #[test]
    fn keepalive() {
        let t = GrpcMuxTransport::default();
        assert!(!t.keepalive_needed());
        t.open_stream();
        assert!(!t.keepalive_needed()); // not yet 5s
    }
}
