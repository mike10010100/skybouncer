//! Property-based tests (`proptest`) for algebraic laws, duration conversions,
//! scheduling bounds, and panic-freedom invariants.
//!
//! This is the canonical home for property tests that exercise **library** behavior
//! (`skybouncer::*`), per the `rust-best-practices` blueprint (`proptest` over
//! `cargo-fuzz`; property tests live in `tests/property_tests.rs`).
//!
//! Adversarial `proptest!` blocks that exercise *test-local speculative* types
//! (the Section 5 type-redesign proposals such as `Confidence`, `AtDid`) remain
//! colocated with those type definitions in `type_redesign_verification_tests.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use proptest::prelude::*;
use std::str::FromStr;
use std::time::{Duration, UNIX_EPOCH};

use skybouncer::classifier::{BounceDuration, HeuristicClassifier, Sensitivity};
use skybouncer::limiter::{EvaluationRateLimiter, RateLimiterConfig};
use skybouncer::matcher::{extract_did_for_collection, extract_did_from_at_uri};
use skybouncer::types::format_system_time_iso8601;

// =============================================================================
// Strategies
// =============================================================================

/// Generates arbitrary [`BounceDuration`] variants, including large custom values.
///
/// `Custom` excludes `0` because `to_db_string` encodes it as `"0"`, which is
/// intentionally parsed back as [`BounceDuration::Permanent`].
fn arb_bounce_duration() -> impl Strategy<Value = BounceDuration> {
    prop_oneof![
        Just(BounceDuration::Permanent),
        Just(BounceDuration::Cooldown24h),
        Just(BounceDuration::Timeout7d),
        Just(BounceDuration::Timeout30d),
        (1u64..=u64::MAX).prop_map(BounceDuration::Custom),
    ]
}

/// Generates arbitrary [`Sensitivity`] levels.
fn arb_sensitivity() -> impl Strategy<Value = Sensitivity> {
    prop_oneof![
        Just(Sensitivity::Low),
        Just(Sensitivity::Medium),
        Just(Sensitivity::High),
    ]
}

// =============================================================================
// Heuristic classifier (moved from classifier_tests.rs)
// =============================================================================

proptest! {
    #[test]
    fn proptest_heuristic_never_panics_on_arbitrary_strings(s in "\\PC*") {
        let classifier = HeuristicClassifier::default();
        let _ = classifier.evaluate_text(&s);
    }

    #[test]
    fn proptest_heuristic_always_detects_embedded_triggers(
        prefix in "[a-zA-Z0-9 ]{0,30}",
        suffix in "[a-zA-Z0-9 ]{0,30}",
    ) {
        let classifier = HeuristicClassifier::default();
        let text = format!("{prefix} connect wallet {suffix}");
        let verdict = classifier.evaluate_text(&text);
        prop_assert!(verdict.is_violation());
    }
}

// =============================================================================
// Duration conversion & scheduling-bounds laws (BounceDuration)
// =============================================================================

proptest! {
    /// `expires_at_us` is `None` exactly for `Permanent`, and never regresses below `now`.
    #[test]
    fn proptest_bounce_expiry_none_iff_permanent(
        d in arb_bounce_duration(),
        now in any::<u64>(),
    ) {
        let expiry = d.expires_at_us(now);
        prop_assert_eq!(expiry.is_none(), matches!(d, BounceDuration::Permanent));
        if let Some(expires_at) = expiry {
            prop_assert!(expires_at >= now);
        }
    }

    /// The elapsed microsecond delta equals the duration's `as_micros` when no saturation
    /// occurs; when `now + duration` overflows, expiry saturates to `u64::MAX`.
    #[test]
    fn proptest_bounce_expiry_delta_matches_duration(
        d in arb_bounce_duration(),
        now in 0u64..1_000_000_000_000_000u64,
    ) {
        if let (Some(expires_at), Some(dur)) = (d.expires_at_us(now), d.to_duration()) {
            let dur_us = u64::try_from(dur.as_micros()).unwrap_or(u64::MAX);
            match now.checked_add(dur_us) {
                Some(exact) => {
                    prop_assert_eq!(expires_at, exact);
                    prop_assert_eq!(expires_at.saturating_sub(now), dur_us);
                }
                None => {
                    prop_assert_eq!(expires_at, u64::MAX, "overflow must saturate to u64::MAX");
                }
            }
        }
    }

    /// Expiry is monotonic non-decreasing in `now` (clock-warp / ordering law).
    #[test]
    fn proptest_bounce_expiry_monotonic_in_now(
        d in arb_bounce_duration(),
        a in any::<u64>(),
        b in any::<u64>(),
    ) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        if let (Some(lo_exp), Some(hi_exp)) = (d.expires_at_us(lo), d.expires_at_us(hi)) {
            prop_assert!(hi_exp >= lo_exp);
        }
    }

    /// Saturation: a non-permanent duration never overflows past `u64::MAX`.
    #[test]
    fn proptest_bounce_expiry_saturates_at_u64_max(d in arb_bounce_duration()) {
        if let Some(expires_at) = d.expires_at_us(u64::MAX) {
            prop_assert_eq!(expires_at, u64::MAX);
        }
    }

    /// Serialization round-trips preserve the effective timeout duration, even when a
    /// `Custom(n)` collides with a canonical variant's second count.
    #[test]
    fn proptest_bounce_db_string_roundtrip_preserves_duration(d in arb_bounce_duration()) {
        let encoded = d.to_db_string();
        let decoded = BounceDuration::from_str(&encoded);
        prop_assert!(decoded.is_ok(), "to_db_string output must always parse back");
        prop_assert_eq!(decoded.unwrap().to_duration(), d.to_duration());
    }

    /// `as_str()` is stable and `Display` matches its human label.
    #[test]
    fn proptest_bounce_as_str_and_display_consistent(d in arb_bounce_duration()) {
        prop_assert_eq!(d.to_string(), d.display_label().to_string());
        prop_assert!(!d.as_str().is_empty());
    }
}

// =============================================================================
// Sensitivity threshold ordering
// =============================================================================

proptest! {
    /// Thresholds always lie in `[0.0, 1.0]`.
    #[test]
    fn proptest_sensitivity_threshold_bounded(s in arb_sensitivity()) {
        let t = s.threshold();
        prop_assert!((0.0..=1.0).contains(&t));
    }

    /// Ordering law: `Low` (precision) > `Medium` > `High` (recall).
    #[test]
    fn proptest_sensitivity_threshold_ordering(_unit in 0u8..1) {
        prop_assert!(Sensitivity::Low.threshold() > Sensitivity::Medium.threshold());
        prop_assert!(Sensitivity::Medium.threshold() > Sensitivity::High.threshold());
    }
}

// =============================================================================
// Rate limiter scheduling bounds
// =============================================================================

proptest! {
    /// A fresh limiter permits exactly `max_evaluations` calls, then denies.
    #[test]
    fn proptest_rate_limiter_permits_exactly_max(m in 1usize..=40) {
        let limiter = EvaluationRateLimiter::new(RateLimiterConfig {
            max_evaluations: m,
            window_duration: Duration::from_secs(3600),
        });
        let did = "did:plc:proptest_subject";

        let mut permitted = 0usize;
        for _ in 0..m {
            prop_assert!(limiter.check_and_record(did));
            permitted += 1;
        }
        prop_assert_eq!(permitted, m);
        prop_assert!(!limiter.check_and_record(did), "limit must deny past max");
    }

    /// `remaining()` starts at `max` and decreases by one per recorded evaluation.
    #[test]
    fn proptest_rate_limiter_remaining_decreases(m in 1usize..=40) {
        let limiter = EvaluationRateLimiter::new(RateLimiterConfig {
            max_evaluations: m,
            window_duration: Duration::from_secs(3600),
        });
        let did = "did:plc:proptest_remaining";

        prop_assert_eq!(limiter.remaining(did), m);
        for expected in (1..=m).rev() {
            prop_assert!(limiter.check_and_record(did));
            prop_assert_eq!(limiter.remaining(did), expected - 1);
        }
        prop_assert_eq!(limiter.remaining(did), 0);
    }

    /// `reset` restores the full allowance after exhaustion.
    #[test]
    fn proptest_rate_limiter_reset_restores_allowance(m in 1usize..=20) {
        let limiter = EvaluationRateLimiter::new(RateLimiterConfig {
            max_evaluations: m,
            window_duration: Duration::from_secs(3600),
        });
        let did = "did:plc:proptest_reset";

        for _ in 0..m {
            prop_assert!(limiter.check_and_record(did));
        }
        prop_assert!(!limiter.check_and_record(did));

        limiter.reset(did);
        prop_assert_eq!(limiter.remaining(did), m);
        prop_assert!(limiter.check_and_record(did));
    }
}

// =============================================================================
// Panic-freedom & well-formedness for parsers and time formatting
// =============================================================================

proptest! {
    /// AT-URI DID extraction never panics for arbitrary inputs.
    #[test]
    fn proptest_extract_did_never_panics(s in ".*") {
        let _ = extract_did_from_at_uri(&s);
        let _ = extract_did_for_collection(&s, "app.bsky.feed.post");
    }

    /// ISO-8601 formatting never panics and always yields a well-formed `...Z` timestamp.
    #[test]
    fn proptest_iso8601_wellformed(secs in 0u64..4_000_000_000u64, millis in 0u32..1000) {
        let time = UNIX_EPOCH + Duration::from_millis(secs * 1000 + u64::from(millis));
        let formatted = format_system_time_iso8601(time);
        prop_assert!(formatted.ends_with('Z'));
        prop_assert!(formatted.contains('T'));
        prop_assert_eq!(formatted.len(), 24);
        prop_assert_eq!(&formatted[10..11], "T");
    }
}
