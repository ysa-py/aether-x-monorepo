//! Multi-tunnel mesh & cascade.
//!
//! Two capabilities that compose with [`crate::buffer_replay`] and
//! [`crate::multipath`] to make transport swaps invisible to the user's TCP
//! socket:
//!
//!   1. **Nested encapsulation** — an *outer* transport (Intranet mTLS, xhttp)
//!      wraps an *inner* protocol (AmneziaWG, ShadowTLS) which wraps the
//!      payload. The wire bytes are an onion; the outer layer is what a censor
//!      sees, the inner layer is what actually carries the tunnel.
//!
//!   2. **Dynamic tunnel chaining** — mid-stream transport **hopping** without
//!      tearing down the client's TCP socket. When the active transport degrades,
//!      [`TunnelCascade::hop`] swaps which transport carries subsequent frames;
//!      the in-flight frames already handed to the old transport are re-injected
//!      onto the new one by [`crate::buffer_replay::RingBufferReplay`], so the
//!      socket above the cascade never observes a gap.
//!
//! The framing here is a compact, self-describing TLV that models real
//! per-layer overhead honestly (each layer adds a header + its declared
//! overhead). Safe Rust only — `#![forbid(unsafe_code)]` compliant.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Where a layer sits in the encapsulation onion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRole {
    /// Outermost on the wire — what a censor observes (Intranet mTLS / xhttp).
    Outer,
    /// Wrapped by the outer transport — the real tunnel protocol
    /// (AmneziaWG / ShadowTLS).
    Inner,
}

/// One layer of the nested encapsulation stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelLayer {
    /// Short label, e.g. "intranet-mtls", "xhttp", "amneziawg", "shadowtls".
    pub name: String,
    pub role: TunnelRole,
    /// Per-frame encapsulation overhead this layer adds (bytes), modelled in
    /// the framed output so throughput maths is honest.
    pub overhead_bytes: u32,
}

impl TunnelLayer {
    /// Convenience constructor.
    #[must_use]
    pub fn new(name: &str, role: TunnelRole, overhead_bytes: u32) -> Self {
        Self {
            name: name.into(),
            role,
            overhead_bytes,
        }
    }
}

/// A byte added per layer header to mark the role (defensive self-check on decap).
const TAG_OUTER: u8 = 0x4F; // 'O'
const TAG_INNER: u8 = 0x49; // 'I'

fn role_tag(role: TunnelRole) -> u8 {
    match role {
        TunnelRole::Outer => TAG_OUTER,
        TunnelRole::Inner => TAG_INNER,
    }
}

/// Wrap `inner` with one layer's framing: [role_tag][name_len:u8][name][overhead:u32][len:u32][payload + overhead padding].
fn frame_layer(layer: &TunnelLayer, inner: &[u8]) -> Vec<u8> {
    let name_bytes = layer.name.as_bytes();
    debug_assert!(name_bytes.len() <= 255, "layer name too long");
    let mut out = Vec::with_capacity(
        1 + 1 + name_bytes.len() + 4 + 4 + inner.len() + layer.overhead_bytes as usize,
    );
    out.push(role_tag(layer.role));
    out.push(name_bytes.len() as u8);
    out.extend_from_slice(name_bytes);
    out.extend(layer.overhead_bytes.to_be_bytes());
    out.extend((inner.len() as u32).to_be_bytes());
    out.extend_from_slice(inner);
    // Model the layer's declared overhead as trailing padding.
    out.resize(out.len() + layer.overhead_bytes as usize, 0x00);
    out
}

/// Strip one layer's framing, returning the inner payload.
fn unframe_layer(buf: &[u8]) -> Result<Vec<u8>, CascadeError> {
    if buf.len() < 10 {
        return Err(CascadeError::Truncated);
    }
    let role = buf[0];
    if role != TAG_OUTER && role != TAG_INNER {
        return Err(CascadeError::BadRoleTag);
    }
    let name_len = buf[1] as usize;
    let header = 1 + 1 + name_len + 4;
    if buf.len() < header + 4 {
        return Err(CascadeError::Truncated);
    }
    let overhead = u32::from_be_bytes([
        buf[2 + name_len],
        buf[3 + name_len],
        buf[4 + name_len],
        buf[5 + name_len],
    ]);
    let len = u32::from_be_bytes([
        buf[header],
        buf[header + 1],
        buf[header + 2],
        buf[header + 3],
    ]) as usize;
    let body_start = header + 4;
    if buf.len() < body_start + len + overhead as usize {
        return Err(CascadeError::Truncated);
    }
    Ok(buf[body_start..body_start + len].to_vec())
}

/// Framing/validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CascadeError {
    /// A frame was shorter than its header declared.
    Truncated,
    /// The role tag byte was neither Outer nor Inner.
    BadRoleTag,
}

/// An ordered cascade of nested tunnel layers plus the currently-active
/// transport carrying the encapsulated frames.
#[derive(Debug)]
pub struct TunnelCascade {
    /// Layers ordered outer → inner. Encapsulation applies inner-first so the
    /// outer layer ends up outermost on the wire.
    layers: Vec<TunnelLayer>,
    active_transport: Mutex<String>,
    hops: AtomicU64,
}

impl TunnelCascade {
    /// Build a cascade from outer→inner layers.
    #[must_use]
    pub fn new(layers: Vec<TunnelLayer>) -> Self {
        Self {
            layers,
            active_transport: Mutex::new("primary".into()),
            hops: AtomicU64::new(0),
        }
    }

    /// A common production shape: Intranet mTLS (outer) over xhttp (outer-ish
    /// disguise) wrapping AmneziaWG (inner) over ShadowTLS (inner). Returns a
    /// ready-made cascade.
    #[must_use]
    pub fn iran_resilient_default() -> Self {
        Self::new(vec![
            TunnelLayer::new("intranet-mtls", TunnelRole::Outer, 48),
            TunnelLayer::new("xhttp", TunnelRole::Outer, 32),
            TunnelLayer::new("amneziawg", TunnelRole::Inner, 64),
            TunnelLayer::new("shadowtls", TunnelRole::Inner, 24),
        ])
    }

    /// Encapsulate a payload through every layer (onion build: inner-first).
    /// The returned bytes are what goes on the wire of the active transport.
    #[must_use]
    pub fn encapsulate(&self, payload: &[u8]) -> Vec<u8> {
        let mut buf = payload.to_vec();
        for layer in self.layers.iter().rev() {
            buf = frame_layer(layer, &buf);
        }
        buf
    }

    /// Decapsulate a framed blob back to the original payload. Validates each
    /// layer's framing; returns the first structural error encountered.
    pub fn decapsulate(&self, framed: &[u8]) -> Result<Vec<u8>, CascadeError> {
        let mut buf = framed.to_vec();
        // Strip in declared order (outer first), matching encapsulate's reverse.
        for _ in &self.layers {
            buf = unframe_layer(&buf)?;
        }
        Ok(buf)
    }

    /// Round-trips the payload through the cascade. Structural framing errors
    /// are returned to the caller; this helper must never convert a malformed
    /// frame into a process panic.
    pub fn roundtrip(&self, payload: &[u8]) -> Result<Vec<u8>, CascadeError> {
        self.decapsulate(&self.encapsulate(payload))
    }

    /// Mid-stream hop: swap the transport carrying subsequent frames **without**
    /// tearing down the client's TCP socket. Returns the new hop count. The
    /// caller re-injects in-flight frames onto `new_transport` via
    /// [`crate::buffer_replay::RingBufferReplay`].
    pub fn hop(&self, new_transport: &str) -> u64 {
        *self.active_transport.lock() = new_transport.to_string();
        self.hops.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// The transport currently carrying frames.
    #[must_use]
    pub fn active_transport(&self) -> String {
        self.active_transport.lock().clone()
    }

    /// Total mid-stream hops performed.
    #[must_use]
    pub fn hop_count(&self) -> u64 {
        self.hops.load(Ordering::SeqCst)
    }

    /// Total declared encapsulation overhead across all layers (bytes/frame).
    #[must_use]
    pub fn total_overhead_bytes(&self) -> u32 {
        self.layers.iter().map(|l| l.overhead_bytes).sum()
    }

    /// Borrow the layer stack (outer → inner).
    #[must_use]
    pub fn layers(&self) -> &[TunnelLayer] {
        &self.layers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn encapsulate_then_decapsulate_is_lossless() {
        let c = TunnelCascade::iran_resilient_default();
        let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
        let framed = c.encapsulate(&payload);
        // Framing adds real overhead per layer.
        assert!(framed.len() > payload.len() + c.total_overhead_bytes() as usize);
        assert_eq!(c.decapsulate(&framed).unwrap(), payload);
    }

    #[test]
    fn roundtrip_helper_is_lossless() {
        let c = TunnelCascade::iran_resilient_default();
        assert_eq!(c.roundtrip(b"hello"), Ok(b"hello".to_vec()));
        assert_eq!(c.roundtrip(&[]), Ok(Vec::<u8>::new()));
    }

    #[test]
    fn mid_stream_hop_preserves_session() {
        let c = TunnelCascade::iran_resilient_default();
        assert_eq!(c.active_transport(), "primary".to_string());
        assert_eq!(c.hop_count(), 0);
        // Hop mid-stream — the cascade (and the socket above it) stays up.
        let n = c.hop("dns-tunnel-masterdns");
        assert_eq!(n, 1);
        assert_eq!(c.active_transport(), "dns-tunnel-masterdns".to_string());
        // Payload still encapsulates/decapsulates identically after the hop.
        assert_eq!(c.roundtrip(b"post-hop data"), Ok(b"post-hop data".to_vec()));
        let _ = c.hop("webtunnel");
        assert_eq!(c.hop_count(), 2);
    }

    #[test]
    fn decapsulate_detects_corruption() {
        let c = TunnelCascade::iran_resilient_default();
        let mut framed = c.encapsulate(b"payload");
        // Corrupt the outermost role tag.
        framed[0] = 0x00;
        assert_eq!(c.decapsulate(&framed), Err(CascadeError::BadRoleTag));
        // Truncated frame.
        assert_eq!(c.decapsulate(&[1, 2, 3]), Err(CascadeError::Truncated));
    }

    #[test]
    fn nested_outer_wraps_inner() {
        // Outer (mTLS) over Inner (amneziawg) — two-layer onion.
        let c = TunnelCascade::new(vec![
            TunnelLayer::new("intranet-mtls", TunnelRole::Outer, 16),
            TunnelLayer::new("amneziawg", TunnelRole::Inner, 32),
        ]);
        let framed = c.encapsulate(b"innermost");
        // The outermost layer's name appears first in the wire bytes.
        let outer_name = "intranet-mtls".as_bytes();
        assert!(framed.windows(outer_name.len()).any(|w| w == outer_name));
        assert_eq!(c.decapsulate(&framed).unwrap(), b"innermost");
    }

    #[test]
    fn cascade_replay_integration_no_gap() {
        // The composition the spec asks for: encapsulate a frame, hand it to a
        // transport, buffer it; on a drop, hop the cascade and replay the
        // in-flight frame onto the winning path — the decapsulated payload on
        // the far side is unchanged (no gap).
        use crate::buffer_replay::RingBufferReplay;
        let cascade = Arc::new(TunnelCascade::iran_resilient_default());
        let replay = Arc::new(RingBufferReplay::new(64));

        let payload = b"sensitive upstream bytes".to_vec();
        let framed = cascade.encapsulate(&payload);
        let _seq = replay.push(framed.clone());

        // Transport drops → hop + replay onto the winning path.
        let _hops = cascade.hop("webtunnel");
        let reinjected = replay.on_drop();
        assert_eq!(reinjected.len(), 1);
        // The re-injected frame decapsulates to the ORIGINAL payload — the peer
        // sees continuity, not a gap.
        assert_eq!(cascade.decapsulate(&reinjected[0].data).unwrap(), payload);
    }

    #[test]
    fn concurrent_hops_and_encap_are_race_free() {
        let c = Arc::new(TunnelCascade::iran_resilient_default());
        let mut handles = Vec::new();
        for i in 0..6 {
            let c = Arc::clone(&c);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = c.hop(&format!("transport-{i}"));
                    let _ = c.encapsulate(b"x");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(c.hop_count(), 600);
    }
}
