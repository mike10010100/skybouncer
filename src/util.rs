//! Small internal utilities shared across modules.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Normalizes a user-supplied handle by trimming surrounding whitespace and a single
/// leading `@`. Preserves case; for strictly-validated/lowercased handles at trust
/// boundaries use [`skyauth::identity::normalize_handle`].
#[must_use]
pub fn normalize_handle(raw: &str) -> &str {
    raw.trim().trim_start_matches('@')
}

/// Maps a string key to a shard index in `[0, shards)` using a stable hash.
///
/// Used for lock striping and partitioned caches so that all concurrent operations
/// targeting the same key serialize on the same shard.
#[must_use]
pub fn shard_index(key: &str, shards: usize) -> usize {
    if shards == 0 {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % shards
}

/// Applies the pragmas shared by every Skybouncer SQLite connection: WAL journaling,
/// `NORMAL` synchronous mode, and a bounded busy timeout.
///
/// Callers remain responsible for connection-specific pragmas (e.g. `foreign_keys`,
/// `temp_store`, `mmap_size`).
///
/// # Errors
/// Returns [`crate::error::SkybouncerError::Database`] if any pragma is rejected.
pub fn apply_common_pragmas(
    conn: &rusqlite::Connection,
    busy_timeout_ms: u32,
) -> Result<(), crate::error::SkybouncerError> {
    use crate::error::SkybouncerError;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| SkybouncerError::Database(format!("Failed to set journal_mode WAL: {e}")))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| SkybouncerError::Database(format!("Failed to set synchronous NORMAL: {e}")))?;
    conn.pragma_update(None, "busy_timeout", busy_timeout_ms)
        .map_err(|e| SkybouncerError::Database(format!("Failed to set busy_timeout: {e}")))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn normalize_handle_trims_and_strips_single_at() {
        assert_eq!(
            normalize_handle("  @alice.bsky.social  "),
            "alice.bsky.social"
        );
        assert_eq!(normalize_handle("@alice"), "alice");
        assert_eq!(normalize_handle("alice"), "alice");
        assert_eq!(normalize_handle("  alice  "), "alice");
        assert_eq!(normalize_handle(""), "");
        assert_eq!(normalize_handle("   "), "");
        // Case is preserved (unlike skyauth's validating normalizer).
        assert_eq!(normalize_handle("@Alice"), "Alice");
        // `trim_start_matches('@')` strips all leading '@' characters.
        assert_eq!(normalize_handle("@@alice"), "alice");
        assert_eq!(normalize_handle("did:plc:abc"), "did:plc:abc");
    }

    #[test]
    fn shard_index_zero_shards_returns_zero() {
        assert_eq!(shard_index("anything", 0), 0);
    }

    #[test]
    fn shard_index_is_deterministic_and_in_range() {
        for key in ["did:plc:alice", "did:plc:bob", "", "x"] {
            let a = shard_index(key, 64);
            let b = shard_index(key, 64);
            assert_eq!(a, b, "same key must hash to the same shard");
            assert!(a < 64);
        }
    }

    #[test]
    fn shard_index_distributes_across_shards() {
        // 1000 distinct keys over 16 shards should hit more than one shard.
        let mut seen = std::collections::HashSet::new();
        for i in 0..1000u32 {
            seen.insert(shard_index(&format!("key-{i}"), 16));
        }
        assert!(seen.len() > 1, "hash must distribute, got {seen:?}");
    }

    #[test]
    fn apply_common_pragmas_succeeds_and_sets_busy_timeout() {
        // In-memory databases use the `memory` journal mode (WAL is unsupported),
        // so assert only the applied timeout, not the journal mode.
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory");
        apply_common_pragmas(&conn, 5000).expect("pragmas apply");

        let busy: i64 = conn
            .pragma_query_value(None, "busy_timeout", |r| r.get(0))
            .expect("busy_timeout");
        assert_eq!(busy, 5000);
    }
}
