#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the adaptive TLS fragmentation engine with arbitrary parameters derived
// from the fuzz input. The engine must never panic and offsets must stay in
// range regardless of input.
fuzz_target!(|data: &[u8]| {
    if data.len() < 13 {
        return;
    }
    let clienthello_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let max_segments = data[4].max(2); // u8, floor at 2
    let seed = u64::from_le_bytes([
        data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12],
    ]);

    let policy = aether_supervisor::fragmentation::FragmentationPolicy {
        enabled: true,
        split_offsets: [None; 4],
        max_segments,
    };
    let len = clienthello_len.max(1); // never zero
    let plan = aether_supervisor::fragmentation::plan(len, policy, seed);

    // Assert offsets are strictly within (0, len).
    for o in &plan.offsets {
        assert!(*o > 0 && *o < len, "offset out of range");
    }
});
