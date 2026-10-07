//! Clock-warp-safe time helpers shared across persistence and engine layers.
//!
//! System clocks can step backwards under VM hypervisors, container suspension, or
//! NTP synchronization. All helpers here clamp rather than panic on such transitions.

/// Returns the current Unix timestamp in microseconds, or `0` if the system clock is
/// set before the Unix epoch.
#[must_use]
pub fn current_time_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or_default())
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
