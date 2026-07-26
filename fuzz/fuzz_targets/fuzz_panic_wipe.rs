//! Fuzz target for panic-wipe engine (Subsystem D).
//!
//! Ensures the panic-wipe engine is robust against malformed inputs
//! and always completes within the time budget.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return; // need at least 32-byte pin hash + 1 byte pin
    }
    let mut pin_hash = [0u8; 32];
    pin_hash.copy_from_slice(&data[..32]);
    let pin = &data[32..];

    let engine = aether_supervisor::panic_wipe::PanicWipeEngine::new(pin_hash);

    // Register some targets.
    let store = aether_supervisor::panic_wipe::SubscriptionStore::new("fuzz-store");
    store.add_subscription(pin.to_vec());
    engine.register_target(Box::new(store));

    let log = aether_supervisor::panic_wipe::LogBuffer::new("fuzz-log");
    log.log("fuzz entry".to_string());
    engine.register_target(Box::new(log));

    // Try triggering with the data as the pin.
    let _ = engine.trigger(pin);
});
