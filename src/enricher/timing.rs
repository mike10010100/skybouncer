//! Zero-dependency UTC timestamp and ATProto TID timing utilities.

use crate::enricher::FORGED_TID_DRIFT_SECS;
use crate::matcher::Interaction;

pub(super) const TID_TIMESTAMP_MIN_US: u64 = 1_577_836_800_000_000;
const TID_TIMESTAMP_MAX_US: u64 = 2_208_988_800_000_000;

/// Extracts the final record key (`rkey`) segment from a canonical `at://did/.../collection/rkey` URI.
#[must_use]
pub fn extract_rkey_from_at_uri(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix("at://")?;
    let mut parts = rest.split('/');
    let did = parts.next()?;
    let collection = parts.next()?;
    let rkey = parts.next()?;
    if parts.next().is_some()
        || !did.starts_with("did:")
        || collection.is_empty()
        || rkey.is_empty()
    {
        return None;
    }
    Some(rkey)
}

/// Decodes a 13-character ATProto base32-sortable TID `rkey` into a Unix microsecond timestamp.
///
/// Rejects malformed lengths, non-TID characters, top bit set (`1 << 63`), and implausible
/// timestamps outside 2020-01-01 through 2040-01-01.
#[must_use]
pub fn decode_tid_timestamp_us(rkey: &str) -> Option<u64> {
    if rkey.len() != 13 {
        return None;
    }
    let mut val: u64 = 0;
    for b in rkey.bytes() {
        let digit = match b {
            b'2'..=b'7' => u64::from(b - b'2'),
            b'a'..=b'z' => u64::from(b - b'a') + 6,
            _ => return None,
        };
        val = (val << 5) | digit;
    }
    if (val & (1_u64 << 63)) != 0 {
        return None;
    }
    let ts_us = val >> 10;
    if !(TID_TIMESTAMP_MIN_US..=TID_TIMESTAMP_MAX_US).contains(&ts_us) {
        return None;
    }
    Some(ts_us)
}

/// Computes local timing signals (`(reply_latency_ms, forged_tid)`) from a candidate interaction
/// without any network calls.
///
/// Returns `(None, false)` for synthetic/zero-timestamp fixtures prior to 2020.
#[must_use]
pub fn compute_reply_timing_signals(interaction: &Interaction) -> (Option<u64>, bool) {
    if interaction.created_at_us < TID_TIMESTAMP_MIN_US {
        return (None, false);
    }
    let forged_tid = extract_rkey_from_at_uri(&interaction.post_uri)
        .and_then(decode_tid_timestamp_us)
        .is_some_and(|post_us| {
            interaction.created_at_us.abs_diff(post_us) > FORGED_TID_DRIFT_SECS * 1_000_000
        });
    let reply_latency_ms = interaction
        .parent_uri
        .as_deref()
        .and_then(extract_rkey_from_at_uri)
        .and_then(decode_tid_timestamp_us)
        .and_then(|parent_us| {
            if parent_us <= interaction.created_at_us.saturating_add(2_000_000) {
                Some(interaction.created_at_us.saturating_sub(parent_us) / 1_000)
            } else {
                None
            }
        });
    (reply_latency_ms, forged_tid)
}

/// Parses an ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SS[.fff](Z|+00:00|-00:00)`) into
/// Unix epoch seconds.
///
/// Rejects non-UTC timezone offsets, years before `1970` or after `9999`, and invalid
/// calendar dates or leap days (e.g. `2025-02-29`). Uses pure integer arithmetic based on
/// Howard Hinnant's `days_from_civil` algorithm with zero external dependencies.
#[must_use]
pub fn parse_iso8601_utc_secs(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    let (date_part, time_and_tz) = trimmed.split_once(['T', 't'])?;
    if date_part.len() != 10 {
        return None;
    }
    let date_bytes = date_part.as_bytes();
    if date_bytes.get(4).copied() != Some(b'-') || date_bytes.get(7).copied() != Some(b'-') {
        return None;
    }
    let year: i64 = date_part.get(0..4)?.parse().ok()?;
    let month: u32 = date_part.get(5..7)?.parse().ok()?;
    let day: u32 = date_part.get(8..10)?.parse().ok()?;
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    if day == 0 || day > max_day {
        return None;
    }

    let time_core = time_and_tz
        .strip_suffix(['Z', 'z'])
        .or_else(|| time_and_tz.strip_suffix("+00:00"))
        .or_else(|| time_and_tz.strip_suffix("-00:00"))?;

    let hms = match time_core.split_once('.') {
        Some((hms_part, frac)) => {
            if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            hms_part
        }
        None => time_core,
    };
    if hms.len() != 8 {
        return None;
    }
    let hms_bytes = hms.as_bytes();
    if hms_bytes.get(2).copied() != Some(b':') || hms_bytes.get(5).copied() != Some(b':') {
        return None;
    }
    let hour: u64 = hms.get(0..2)?.parse().ok()?;
    let minute: u64 = hms.get(3..5)?.parse().ok()?;
    let second: u64 = hms.get(6..8)?.parse().ok()?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    let day_secs = days.checked_mul(86_400)?;
    day_secs.checked_add(hour * 3_600 + minute * 60 + second)
}

const fn days_from_civil(year: i64, month: u32, day: u32) -> Option<u64> {
    let m = month as i64;
    let d = day as i64;
    let y = if m <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    if days < 0 {
        None
    } else {
        Some(days as u64)
    }
}
