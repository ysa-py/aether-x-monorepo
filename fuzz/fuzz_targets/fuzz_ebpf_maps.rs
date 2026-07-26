// Fuzz the eBPF userspace wrapper (MockRstDropper) with arbitrary byte arrays.
// Exercises add_dpi_source / remove_dpi_source / detach operations. Asserts
// zero panics, zero index out-of-bounds, and zero memory leaks under ASan.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut dropper = aether_supervisor::ebpf::MockRstDropper::new();
    use aether_supervisor::ebpf::RstDropper; // bring trait into scope
    let _ = dropper.load("eth0");

    // Derive u32 IPs from the fuzz input in 4-byte chunks and add them.
    for chunk in data.chunks(4) {
        let mut buf = [0u8; 4];
        let n = chunk.len().min(4);
        buf[..n].copy_from_slice(&chunk[..n]);
        let ip = u32::from_le_bytes(buf);
        let _ = dropper.add_dpi_source(ip);
    }

    // Remove IPs derived from 8-byte chunks (different alignment).
    for chunk in data.chunks(8) {
        if chunk.len() >= 4 {
            let ip = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let _ = dropper.remove_dpi_source(ip);
        }
    }

    // Exercise trait queries.
    let _ = dropper.is_active();
    let _ = dropper.dpi_source_count();

    // Detach and verify lifecycle completes cleanly.
    let _ = dropper.detach();
});
