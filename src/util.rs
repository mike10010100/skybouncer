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
