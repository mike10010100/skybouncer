//! Clock-warp-safe time helpers shared across persistence and engine layers.
//!
//! System clocks can step backwards under VM hypervisors, container suspension, or
//! NTP synchronization. All helpers here clamp rather than panic on such transitions.

static MONOTONIC_ANCHOR: std::sync::OnceLock<(std::time::Instant, u64)> =
    std::sync::OnceLock::new();

/// Returns the current Unix timestamp in microseconds, or `0` if the system clock is
/// set before the Unix epoch.
#[must_use]
pub fn current_time_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or_default())
}

/// Returns a monotonically non-decreasing microsecond timestamp anchored to the
/// Unix epoch at first call, immune to backward wall-clock steps.
#[must_use]
pub fn monotonic_time_us() -> u64 {
    let (base_instant, base_unix_us) =
        *MONOTONIC_ANCHOR.get_or_init(|| (std::time::Instant::now(), current_time_us()));
    let elapsed_us = u64::try_from(
        std::time::Instant::now()
            .saturating_duration_since(base_instant)
            .as_micros(),
    )
    .unwrap_or(u64::MAX);
    base_unix_us.saturating_add(elapsed_us)
}

/// Converts an unsigned microsecond timestamp into a SQLite `INTEGER`, saturating at
/// [`i64::MAX`] for values that exceed the signed range.
#[must_use]
pub fn us_to_i64(us: u64) -> i64 {
    i64::try_from(us).unwrap_or(i64::MAX)
}

/// Converts a SQLite `INTEGER` into an unsigned microsecond timestamp, clamping any
/// negative value to `0`.
#[must_use]
pub fn i64_to_us(value: i64) -> u64 {
    u64::try_from(value.max(0)).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn monotonic_time_us_advances_and_matches_epoch_scale() {
        let t1 = monotonic_time_us();
        assert!(t1 > 1_000_000_000_000_000);
        std::thread::sleep(Duration::from_millis(2));
        let t2 = monotonic_time_us();
        assert!(t2 > t1);
        assert!(t2 - t1 >= 1_000);
    }

    #[test]
    fn us_i64_roundtrip_and_clamping() {
        assert_eq!(us_to_i64(42), 42);
        assert_eq!(us_to_i64(u64::MAX), i64::MAX);
        assert_eq!(i64_to_us(42), 42);
        assert_eq!(i64_to_us(-5), 0);
    }
}
