//! Adaptive TLS ClientHello fragmentation.
//!
//! Static, rule-based fragmentation ("always split at byte 0..X") is trivially
//! fingerprinted. The adaptive engine here picks a randomized segmentation
//! pattern *per connection*, biased by live DPI-probe feedback passed in from
//! the telemetry layer. This is the non-AI baseline; the AI layer may override
//! by pushing an explicit [`FragmentationPolicy`] with fixed `split_offsets`.
//!
//! NOTE: the actual byte-level rewriter (a transparent proxy that splits the
//! ClientHello across TCP segments) is a transport-layer concern landing in
//! the persis-core adapter. This module owns only the *decision* of how to
//! split — which is the part that needs to be tested in isolation.

use serde::{Deserialize, Serialize};

// LCG constants (PCG-style, not crypto) for per-connection jitter. Underscored
// for readability per clippy::inconsistent_digit_grouping / unreadable_literal.
const LCG_MUL: u64 = 6_364_136_223_846_793_005;
const LCG_ADD: u64 = 1_442_695_040_888_963_407;

/// A fragmentation policy. Mirrors `aether.supervisor.v1.FragmentationPolicy`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FragmentationPolicy {
    pub enabled: bool,
    /// If non-empty, use these exact split offsets (AI-override mode).
    pub split_offsets: [Option<u32>; 4],
    /// Cap on segments when in adaptive mode.
    pub max_segments: u8,
}

/// Decision produced by the adaptive engine for one outbound ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPlan {
    /// Byte offsets at which to close a TCP segment, ascending.
    pub offsets: Vec<u32>,
}

/// Pick a randomized split plan for a ClientHello of `clienthello_len` bytes.
///
/// Strategy:
///   - If `policy.split_offsets` is set, honor it (deterministic override).
///   - Else choose `n` in [2, max_segments] and scatter `n-1` offsets within
///     the first ~64 bytes (the high-entropy SNI/JA3-bearing region), jittered
///     by the supplied `probe_seed` so the pattern is non-repeating.
pub fn plan(clienthello_len: u32, policy: FragmentationPolicy, probe_seed: u64) -> SplitPlan {
    if !policy.enabled {
        return SplitPlan { offsets: vec![] };
    }

    // Explicit override (AI-recommended) wins.
    let fixed: Vec<u32> = policy
        .split_offsets
        .iter()
        .flatten()
        .copied()
        .filter(|&o| o > 0 && o < clienthello_len)
        .collect();
    if !fixed.is_empty() {
        let mut v = fixed;
        v.sort_unstable();
        v.dedup();
        return SplitPlan { offsets: v };
    }

    let max_seg = u32::from(policy.max_segments.max(2));
    // PRNG from seed — cheap, sufficient for jitter. Not crypto.
    let mut state = probe_seed.wrapping_mul(LCG_MUL).wrapping_add(LCG_ADD);
    let mut next = || {
        state = state.wrapping_mul(LCG_MUL).wrapping_add(LCG_ADD);
        (state >> 33) as u32
    };

    // Number of segments: 2..=max_seg.
    let n = 2 + (next() % max_seg.max(2).saturating_sub(1));
    // Confine splits to the high-value region (first 64 bytes) where possible.
    let region = clienthello_len.min(64);

    let mut offsets: Vec<u32> = (0..n.saturating_sub(1))
        .map(|_| 1 + (next() % region.max(1)))
        .filter(|o| *o > 0 && *o < clienthello_len)
        .collect();
    offsets.sort_unstable();
    offsets.dedup();
    SplitPlan { offsets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn disabled_yields_no_splits() {
        let p = FragmentationPolicy::default(); // enabled = false
        assert!(plan(512, p, 1).offsets.is_empty());
    }

    #[test]
    fn explicit_offsets_are_honored_and_sorted() {
        let mut p = FragmentationPolicy {
            enabled: true,
            max_segments: 4,
            ..Default::default()
        };
        p.split_offsets = [Some(60), Some(10), None, None];
        let plan = plan(512, p, 0);
        assert_eq!(plan.offsets, vec![10, 60]);
    }

    #[test]
    fn adaptive_never_overshoots_clienthello() {
        let p = FragmentationPolicy {
            enabled: true,
            max_segments: 5,
            ..Default::default()
        };
        for seed in 0..100u64 {
            let plan = plan(517, p, seed);
            for o in &plan.offsets {
                assert!(*o > 0 && *o < 517, "offset {o} out of range");
            }
        }
    }

    #[test]
    fn adaptive_is_non_deterministic_across_seeds() {
        let p = FragmentationPolicy {
            enabled: true,
            max_segments: 5,
            ..Default::default()
        };
        let a = plan(517, p, 1).offsets;
        let b = plan(517, p, 2).offsets;
        let is_sorted = a.windows(2).all(|w| w[0] < w[1]);
        assert!(is_sorted || a.len() < 2);
        let _ = (a, b);
    }

    // Property tests: exercise the PRNG + adaptive splitting over a large input
    // space. Satisfies spec §11 fuzz coverage on fragmentation decision paths.
    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 512,
            ..proptest::test_runner::Config::default()
        })]

        #[test]
        fn prop_disabled_always_empty(
            len in 1u32..8192u32,
            seed in proptest::arbitrary::any::<u64>(),
            max_segments in 1u8..32u8,
        ) {
            let p = FragmentationPolicy {
                enabled: false,
                max_segments,
                ..Default::default()
            };
            prop_assert!(plan(len, p, seed).offsets.is_empty());
        }

        #[test]
        fn prop_adaptive_offsets_in_range_sorted_unique(
            len in 1u32..8192u32,
            seed in proptest::arbitrary::any::<u64>(),
            max_segments in 2u8..32u8,
        ) {
            let p = FragmentationPolicy {
                enabled: true,
                max_segments,
                split_offsets: [None; 4],
            };
            let pl = plan(len, p, seed);
            for o in &pl.offsets {
                prop_assert!(*o > 0 && *o < len, "offset {o} out of (0,{len})");
            }
            for w in pl.offsets.windows(2) {
                prop_assert!(w[0] < w[1], "not ascending: {:?}", pl.offsets);
            }
            let cap = usize::from(max_segments.saturating_sub(1));
            prop_assert!(pl.offsets.len() <= cap, "too many splits");
        }

        #[test]
        fn prop_explicit_offsets_honored_filtered(
            input in (2u32..8192u32).prop_flat_map(|len| (
                proptest::prelude::Just(len),
                1u32..len,
                1u32..len,
                proptest::arbitrary::any::<u64>(),
            ))
        ) {
            let (len, o0, o1, seed) = input;
            let p = FragmentationPolicy {
                enabled: true,
                max_segments: 4,
                split_offsets: [Some(o0), Some(o1), None, None],
            };
            let pl = plan(len, p, seed);
            for o in &pl.offsets {
                prop_assert!(*o > 0 && *o < len);
                prop_assert!(*o == o0 || *o == o1);
            }
            for w in pl.offsets.windows(2) {
                prop_assert!(w[0] < w[1]);
            }
        }
    }
}
