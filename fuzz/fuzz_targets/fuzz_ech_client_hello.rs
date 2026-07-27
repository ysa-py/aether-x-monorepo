#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the TLS ClientHello extension parser (SNI + ECH 0xfe0d) with arbitrary
// byte slices. The parser must never panic on any input — it returns Result.
fuzz_target!(|data: &[u8]| {
    let _ = aether_supervisor::tls::parse_extensions(data);
});
