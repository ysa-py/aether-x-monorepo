#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the Iran-aware routing engine with arbitrary domain strings and IP
/// addresses. The engine must never panic and must always return a valid Action.
fuzz_target!(|data: &[u8]| {
    let domain = std::str::from_utf8(data).unwrap_or("");
    let engine = aether_routing::Engine::new(aether_routing::preset());

    // Domain-based decision.
    let _ = engine.decide(&aether_routing::Request {
        domain: Some(domain),
        ip: None,
    });

    // If the input parses as an IP, also test IP-based routing.
    if let Ok(ip) = domain.parse::<std::net::IpAddr>() {
        let _ = engine.decide(&aether_routing::Request {
            domain: None,
            ip: Some(ip),
        });
    }
});
