//! ICMP payload encapsulation tunneling
//!
//! When DPI blocks TCP/QUIC but allows ICMP (ping), this module encapsulates
//! data inside ICMP Echo Request/Reply payloads. Naturally rate-limited and
//! low-throughput, but survives extreme blackout.
//!
//! Framing: [MAGIC 2 bytes][SEQ 2 bytes][LEN 2 bytes][DATA][CRC16 2 bytes]
//! Real ICMP tunnel implementations (e.g. ptunnel) use similar framing.

use std::collections::HashMap;
use parking_lot::RwLock;

/// ICMP tunnel frame magic.
const MAGIC: u16 = 0xAE11;

/// Encode data into ICMP payload.
#[must_use]
pub fn encode_icmp_payload(seq: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 8);
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    let crc = crc16(data);
    out.extend_from_slice(&crc.to_be_bytes());
    out
}

/// Decode ICMP payload to original data.
pub fn decode_icmp_payload(payload: &[u8]) -> Result<(u16, Vec<u8>), IcmpError> {
    if payload.len() < 8 {
        return Err(IcmpError::Truncated);
    }
    let magic = u16::from_be_bytes([payload[0], payload[1]]);
    if magic != MAGIC {
        return Err(IcmpError::BadMagic);
    }
    let seq = u16::from_be_bytes([payload[2], payload[3]]);
    let len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if payload.len() < 6 + len + 2 {
        return Err(IcmpError::Truncated);
    }
    let data = payload[6..6 + len].to_vec();
    let crc_expected = u16::from_be_bytes([payload[6 + len], payload[6 + len + 1]]);
    let crc_actual = crc16(&data);
    if crc_expected != crc_actual {
        return Err(IcmpError::CrcMismatch);
    }
    Ok((seq, data))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcmpError {
    Truncated,
    BadMagic,
    CrcMismatch,
}

/// CRC16-CCITT (simple implementation)
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// ICMP tunnel session (reassembly of fragmented encapsulated data).
#[derive(Debug)]
pub struct IcmpTunnel {
    next_seq: u16,
    recv_buffer: RwLock<HashMap<u16, Vec<u8>>>,
    bytes_encap: std::sync::atomic::AtomicU64,
}

impl IcmpTunnel {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_seq: 0,
            recv_buffer: RwLock::new(HashMap::new()),
            bytes_encap: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Encapsulate data for sending via ICMP.
    pub fn encapsulate(&mut self, data: &[u8]) -> Vec<u8> {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.bytes_encap.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
        encode_icmp_payload(seq, data)
    }

    /// Decapsulate incoming ICMP payload.
    pub fn decapsulate(&self, payload: &[u8]) -> Result<Vec<u8>, IcmpError> {
        let (seq, data) = decode_icmp_payload(payload)?;
        {
            let mut buf = self.recv_buffer.write();
            buf.insert(seq, data.clone());
        }
        Ok(data)
    }

    #[must_use]
    pub fn bytes_encapsulated(&self) -> u64 {
        self.bytes_encap.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[must_use]
    pub fn pending_fragments(&self) -> usize {
        self.recv_buffer.read().len()
    }
}

impl Default for IcmpTunnel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"hello icmp tunnel under blackout";
        let payload = encode_icmp_payload(42, data);
        let (seq, decoded) = decode_icmp_payload(&payload).unwrap();
        assert_eq!(seq, 42);
        assert_eq!(decoded, data);
    }

    #[test]
    fn reject_bad_magic() {
        let mut payload = encode_icmp_payload(1, b"test");
        payload[0] = 0x00;
        assert_eq!(decode_icmp_payload(&payload).unwrap_err(), IcmpError::BadMagic);
    }

    #[test]
    fn reject_truncated() {
        assert_eq!(decode_icmp_payload(&[0xAE, 0x11, 0x00]).unwrap_err(), IcmpError::Truncated);
    }

    #[test]
    fn reject_crc_mismatch() {
        let mut payload = encode_icmp_payload(1, b"test");
        let last = payload.len() - 1;
        payload[last] ^= 0xFF;
        assert_eq!(decode_icmp_payload(&payload).unwrap_err(), IcmpError::CrcMismatch);
    }

    #[test]
    fn tunnel_session() {
        let mut tun = IcmpTunnel::new();
        let p1 = tun.encapsulate(b"chunk1");
        let p2 = tun.encapsulate(b"chunk2");
        assert_eq!(tun.bytes_encapsulated(), 12);
        let d1 = tun.decapsulate(&p1).unwrap();
        assert_eq!(d1, b"chunk1");
        let d2 = tun.decapsulate(&p2).unwrap();
        assert_eq!(d2, b"chunk2");
        assert_eq!(tun.pending_fragments(), 2);
    }

    #[test]
    fn empty_data() {
        let payload = encode_icmp_payload(0, b"");
        let (seq, data) = decode_icmp_payload(&payload).unwrap();
        assert_eq!(seq, 0);
        assert!(data.is_empty());
    }
}
