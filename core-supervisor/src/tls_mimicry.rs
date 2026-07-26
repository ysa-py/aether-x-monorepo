//! Zero-RTT TLS 1.3 mimicry: VLESS-REALITY & ShadowTLS v3
//!
//! Implements TLS fingerprint mimicry to defend against active probing:
//! - VLESS-REALITY: disguises as a real TLS server's handshake using the
//!   server's public key and whitelisted SNI. Probes to our server show the
//!   real site (e.g. digikala) not a proxy.
//! - ShadowTLS v3: wraps any protocol in a genuine TLS handshake to a
//!   whitelisted server; after handshake, the connection is handed to the
//!   inner protocol.
//! - Zero-RTT: for TUIC/Hysteria2 compatibility, allows 0-RTT data where safe.
//!
//! All crypto operations are modeled deterministically; real TLS uses rustls.

use parking_lot::RwLock;
use std::time::{Duration, Instant};

/// TLS mimicry mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimicryMode {
    Reality,
    ShadowTlsV3,
    ZeroRtt,
    Boring, // plain TLS as Chrome
}

/// Configuration for REALITY.
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// Server name to mimic (whitelisted domestic SNI).
    pub server_name: String,
    /// Public key of the real server (for REALITY handshake verification).
    pub public_key: String,
    /// Short ID used to identify client.
    pub short_id: String,
    /// Dest address: where to forward if probe detected.
    pub dest: String,
    /// SpiderX: path to mimic real site's behavior.
    pub spider_x: String,
}

impl RealityConfig {
    pub fn new(server_name: &str, public_key: &str) -> Self {
        Self {
            server_name: server_name.to_string(),
            public_key: public_key.to_string(),
            short_id: String::new(),
            dest: format!("{server_name}:443"),
            spider_x: "/".to_string(),
        }
    }
}

/// Configuration for ShadowTLS v3.
#[derive(Debug, Clone)]
pub struct ShadowTlsConfig {
    /// SNI for outer TLS (whitelisted).
    pub sni: String,
    /// Password for inner authentication (HMAC).
    pub password: String,
    /// Version: must be 3 for v3.
    pub version: u8,
}

impl ShadowTlsConfig {
    pub fn v3(sni: &str, password: &str) -> Self {
        Self {
            sni: sni.to_string(),
            password: password.to_string(),
            version: 3,
        }
    }
}

/// TLS ClientHello mimicry template (JA3/JA4)
#[derive(Debug, Clone)]
pub struct TlsMimicTemplate {
    pub mode: MimicryMode,
    /// Cipher suites in preference order (e.g. Chrome's list)
    pub cipher_suites: Vec<u16>,
    /// Extensions in order.
    pub extensions: Vec<u16>,
    /// ALPN: h2, http/1.1 etc
    pub alpn: Vec<String>,
    /// GREASE enabled
    pub grease: bool,
    /// uTLS fingerprint ID (e.g. chrome_120)
    pub utls_fingerprint: String,
}

impl TlsMimicTemplate {
    /// Chrome 120 fingerprint (most common whitelisted)
    #[must_use]
    pub fn chrome_120() -> Self {
        Self {
            mode: MimicryMode::Boring,
            cipher_suites: vec![4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172],
            extensions: vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513],
            alpn: vec!["h2".into(), "http/1.1".into()],
            grease: true,
            utls_fingerprint: "chrome_120".into(),
        }
    }

    /// Reality mode: mimicry of dest server, not Chrome
    #[must_use]
    pub fn reality(dest: &str) -> Self {
        Self {
            mode: MimicryMode::Reality,
            cipher_suites: vec![4865, 4866, 4867],
            extensions: vec![0, 11, 10, 16, 43, 51, 13],
            alpn: vec!["h2".into()],
            grease: true,
            utls_fingerprint: format!("reality_{dest}"),
        }
    }

    /// ShadowTLS v3: genuine TLS handshake to SNI
    #[must_use]
    pub fn shadowtls_v3(sni: &str) -> Self {
        Self {
            mode: MimicryMode::ShadowTlsV3,
            cipher_suites: vec![4865, 4866, 4867, 49195, 49199],
            extensions: vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43],
            alpn: vec!["h2".into(), "http/1.1".into()],
            grease: true,
            utls_fingerprint: format!("shadowtls_v3_{sni}"),
        }
    }
}

/// Active probing defense state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// Looks like real browser -> allow
    Legitimate,
    /// Detected as active probe (e.g. non-browser JA4, missing extension)
    Probe,
    /// Uncertain -> challenge / forward to dest
    UncertainForwardToDest,
}

/// The TLS mimicry engine.
#[derive(Debug)]
pub struct TlsMimicryEngine {
    reality: RwLock<Option<RealityConfig>>,
    shadowtls: RwLock<Option<ShadowTlsConfig>>,
    template: RwLock<TlsMimicTemplate>,
    probes_blocked: std::sync::atomic::AtomicU64,
}

impl TlsMimicryEngine {
    #[must_use]
    pub fn new(template: TlsMimicTemplate) -> Self {
        Self {
            reality: RwLock::new(None),
            shadowtls: RwLock::new(None),
            template: RwLock::new(template),
            probes_blocked: std::sync::atomic::AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn with_chrome() -> Self {
        Self::new(TlsMimicTemplate::chrome_120())
    }

    pub fn set_reality(&self, cfg: RealityConfig) {
        *self.reality.write() = Some(cfg);
    }

    pub fn set_shadowtls(&self, cfg: ShadowTlsConfig) {
        *self.shadowtls.write() = Some(cfg);
    }

    /// Evaluate whether incoming handshake is a probe.
    pub fn evaluate_probe(&self, offered_ciphers: &[u16], offered_extensions: &[u16]) -> ProbeVerdict {
        // Simple heuristics: if client offers only 1 cipher or missing common extensions, likely probe
        if offered_ciphers.len() <= 2 {
            self.probes_blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return ProbeVerdict::Probe;
        }
        if !offered_extensions.contains(&0) {
            // No SNI extension -> likely probe scanner
            self.probes_blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return ProbeVerdict::Probe;
        }
        // If template exists and ciphers overlap significantly -> legitimate
        let tmpl = self.template.read();
        let overlap = offered_ciphers.iter().filter(|c| tmpl.cipher_suites.contains(c)).count();
        if overlap >= 3 {
            ProbeVerdict::Legitimate
        } else {
            // Uncertain: forward to real dest to look legitimate (REALITY behavior)
            ProbeVerdict::UncertainForwardToDest
        }
    }

    /// Generate 0-RTT early data blob if enabled (for Hysteria2/TUIC)
    #[must_use]
    pub fn zero_rtt_blob(&self, seed: u64, data: &[u8]) -> Option<Vec<u8>> {
        let tmpl = self.template.read();
        if tmpl.mode != MimicryMode::ZeroRtt && tmpl.mode != MimicryMode::Reality {
            return None;
        }
        // Simple: prepend deterministic nonce for replay protection
        let mut out = Vec::with_capacity(data.len() + 16);
        out.extend_from_slice(&seed.to_be_bytes());
        out.extend_from_slice(&Instant::now().elapsed().as_nanos().to_be_bytes()[0..8]);
        out.extend_from_slice(data);
        Some(out)
    }

    #[must_use]
    pub fn probes_blocked(&self) -> u64 {
        self.probes_blocked.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[must_use]
    pub fn current_template(&self) -> TlsMimicTemplate {
        self.template.read().clone()
    }

    pub fn rotate_template(&self, new_template: TlsMimicTemplate) {
        *self.template.write() = new_template;
    }
}

impl Default for TlsMimicryEngine {
    fn default() -> Self {
        Self::with_chrome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_template_is_boring() {
        let t = TlsMimicTemplate::chrome_120();
        assert_eq!(t.mode, MimicryMode::Boring);
        assert!(t.cipher_suites.len() > 5);
    }

    #[test]
    fn probe_detection() {
        let eng = TlsMimicryEngine::with_chrome();
        // Probe: only 1 cipher
        let v = eng.evaluate_probe(&[4865], &[0, 11]);
        assert_eq!(v, ProbeVerdict::Probe);
        assert_eq!(eng.probes_blocked(), 1);

        // Legitimate: Chrome-like
        let chrome_ciphers = TlsMimicTemplate::chrome_120().cipher_suites;
        let v2 = eng.evaluate_probe(&chrome_ciphers, &[0, 23, 65281, 10, 11]);
        assert_eq!(v2, ProbeVerdict::Legitimate);
    }

    #[test]
    fn no_sni_is_probe() {
        let eng = TlsMimicryEngine::with_chrome();
        let v = eng.evaluate_probe(&[4865, 4866, 4867, 49195], &[11, 10]);
        assert_eq!(v, ProbeVerdict::Probe);
    }

    #[test]
    fn zero_rtt_blob() {
        let mut eng = TlsMimicryEngine::new(TlsMimicTemplate {
            mode: MimicryMode::ZeroRtt,
            ..TlsMimicTemplate::chrome_120()
        });
        let blob = eng.zero_rtt_blob(42, b"early data").unwrap();
        assert!(blob.len() > 10);
        // Non-zeroRTT mode returns None
        let eng2 = TlsMimicryEngine::with_chrome();
        assert!(eng2.zero_rtt_blob(1, b"x").is_none());
    }

    #[test]
    fn shadowtls_template() {
        let t = TlsMimicTemplate::shadowtls_v3("www.digikala.com");
        assert_eq!(t.mode, MimicryMode::ShadowTlsV3);
        assert!(t.utls_fingerprint.contains("digikala"));
    }

    #[test]
    fn reality_template() {
        let t = TlsMimicTemplate::reality("www.aparat.com");
        assert_eq!(t.mode, MimicryMode::Reality);
    }
}
