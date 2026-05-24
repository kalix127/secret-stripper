// Property-based invariants for the entropy scanner.

use proptest::prelude::*;
use secret_stripper::detector::entropy::{find_high_entropy_strings, shannon_entropy};

proptest! {
    // Integration-test targets have no crate source root, so the default
    // file-based failure persistence cannot resolve a path; disable it.
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

    // A string made of a single repeated character has ~zero entropy,
    // regardless of length.
    #[test]
    fn low_variety_strings_have_low_entropy(c in prop::char::range('a', 'b'), n in 8usize..256) {
        let s: String = std::iter::repeat_n(c, n).collect();
        prop_assert!(shannon_entropy(&s) < 1.5);
    }

    // Tokens shorter than min_len are never returned.
    #[test]
    fn min_len_floor_is_respected(
        min_len in 8usize..32,
        threshold in 0.0f64..2.0,
        body in "[A-Za-z0-9]{1,7}",
    ) {
        let r = find_high_entropy_strings(&body, min_len, 256, threshold);
        prop_assert!(r.is_empty());
    }

    // Monotonicity: a higher threshold can never produce more hits than a
    // lower one on the same input.
    #[test]
    fn threshold_monotonicity(t1 in 0.0f64..6.0, t2 in 0.0f64..6.0, body in ".{0,200}") {
        let (lo, hi) = if t1 < t2 { (t1, t2) } else { (t2, t1) };
        let a = find_high_entropy_strings(&body, 8, 256, lo).len();
        let b = find_high_entropy_strings(&body, 8, 256, hi).len();
        prop_assert!(b <= a);
    }
}
