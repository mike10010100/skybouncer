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

/// Normalizes a user-supplied handle or DID, automatically appending `.bsky.social`
/// when the input is a bare single-label handle without a dot (e.g. `"alice"` or `"@alice"`
/// -> `"alice.bsky.social"`).
///
/// Reserved single-label hostnames (`"localhost"`, `"local"`, `"invalid"`, etc.), numeric
/// literals, and `did:` identifiers are returned without appending `.bsky.social`.
#[must_use]
pub fn normalize_handle_or_default(raw: &str) -> String {
    let clean = normalize_handle(raw).trim();
    skyauth::identity::normalize_user_handle(clean).unwrap_or_else(|_| clean.to_string())
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

/// Applies the pragmas shared by every Skybouncer SQLite connection: busy timeout,
/// incremental auto-vacuum, WAL journaling, `NORMAL` synchronous mode, and a 64 MiB
/// journal size limit.
///
/// `busy_timeout` is configured **first** so subsequent pragmas (such as `journal_mode = WAL`)
/// wait up to `busy_timeout_ms` rather than failing immediately with `SQLITE_BUSY` when
/// opening a contended database.
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
    conn.pragma_update(None, "busy_timeout", busy_timeout_ms)
        .map_err(|e| SkybouncerError::Database(format!("Failed to set busy_timeout: {e}")))?;
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")
        .map_err(|e| {
            SkybouncerError::Database(format!("Failed to set auto_vacuum INCREMENTAL: {e}"))
        })?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| SkybouncerError::Database(format!("Failed to set journal_mode WAL: {e}")))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| SkybouncerError::Database(format!("Failed to set synchronous NORMAL: {e}")))?;
    conn.pragma_update(None, "journal_size_limit", 67_108_864_i64)
        .map_err(|e| SkybouncerError::Database(format!("Failed to set journal_size_limit: {e}")))?;
    Ok(())
}

/// Unpacks SQLite's 32-bit `PRAGMA user_version` into `(tenant_schema_ver, cache_schema_ver)`.
///
/// The low 16 bits store `DeduplicationCache`'s schema version and bits `16..=30` store
/// `TenantRegistry`'s schema version so both subsystems can share one SQLite file without
/// colliding. Negative `user_version` values clamp to `(0, 0)`.
#[must_use]
pub(crate) fn unpack_schema_versions(user_version: i32) -> (u16, u16) {
    let raw = u32::try_from(user_version.max(0)).unwrap_or(0);
    let cache_ver = u16::try_from(raw & 0xFFFF).unwrap_or(0);
    let tenant_ver = u16::try_from((raw >> 16) & 0x7FFF).unwrap_or(0);
    (tenant_ver, cache_ver)
}

/// Packs `(tenant_schema_ver, cache_schema_ver)` into a non-negative 32-bit `PRAGMA user_version`.
#[must_use]
pub(crate) fn pack_schema_versions(tenant_ver: u16, cache_ver: u16) -> i32 {
    let t = i32::from(tenant_ver & 0x7FFF);
    let c = i32::from(cache_ver);
    (t << 16) + c
}

/// Validates that a tenant/protected DID argument is non-empty after trimming whitespace,
/// failing closed with [`crate::error::SkybouncerError::Config`] otherwise.
pub(crate) fn require_non_empty_did<'a>(
    did: &'a str,
    label: &str,
) -> Result<&'a str, crate::error::SkybouncerError> {
    let clean = did.trim();
    if clean.is_empty() {
        return Err(crate::error::SkybouncerError::Config(format!(
            "{label} cannot be empty"
        )));
    }
    Ok(clean)
}

/// Returns `true` if a PDS error string indicates a missing record (`RecordNotFound` /
/// `CouldNotFindRecord` / `"Could not locate record"` / `"Could not find record"`).
///
/// Intentionally does NOT match raw `"404"` substrings, avoiding misclassifying proxy/gateway
/// 404 HTML responses as missing records.
pub(crate) fn is_pds_record_not_found(msg: &str) -> bool {
    msg.contains("CouldNotFindRecord")
        || msg.contains("RecordNotFound")
        || msg.contains("Could not locate record")
        || msg.contains("Could not find record")
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
    fn normalize_handle_or_default_completes_bare_handles() {
        assert_eq!(normalize_handle_or_default("alice"), "alice.bsky.social");
        assert_eq!(
            normalize_handle_or_default("  @Alice  "),
            "alice.bsky.social"
        );
        assert_eq!(
            normalize_handle_or_default("alice.custom.org"),
            "alice.custom.org"
        );
        assert_eq!(normalize_handle_or_default("did:plc:abc"), "did:plc:abc");
        assert_eq!(normalize_handle_or_default("localhost"), "localhost");
        assert_eq!(normalize_handle_or_default(""), "");
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
        // so assert the applied non-default timeout and synchronous NORMAL (1).
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory");
        apply_common_pragmas(&conn, 4321).expect("pragmas apply");

        let busy: i64 = conn
            .pragma_query_value(None, "busy_timeout", |r| r.get(0))
            .expect("busy_timeout");
        assert_eq!(busy, 4321);

        let sync_mode: i64 = conn
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .expect("synchronous");
        assert_eq!(sync_mode, 1);

        let auto_vacuum: i64 = conn
            .pragma_query_value(None, "auto_vacuum", |r| r.get(0))
            .expect("auto_vacuum");
        assert_eq!(auto_vacuum, 2);
    }

    #[test]
    fn apply_common_pragmas_file_backed_sets_wal_auto_vacuum_and_journal_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("pragmas.db");
        let conn = rusqlite::Connection::open(&db_path).expect("open file db");
        apply_common_pragmas(&conn, 5123).expect("pragmas apply");

        let busy: i64 = conn
            .pragma_query_value(None, "busy_timeout", |r| r.get(0))
            .expect("busy_timeout");
        assert_eq!(busy, 5123);

        let auto_vacuum: i64 = conn
            .pragma_query_value(None, "auto_vacuum", |r| r.get(0))
            .expect("auto_vacuum");
        assert_eq!(auto_vacuum, 2, "INCREMENTAL auto_vacuum == 2");

        let journal_mode: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .expect("journal_mode");
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");

        let sync_mode: i64 = conn
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .expect("synchronous");
        assert_eq!(sync_mode, 1);

        let journal_size_limit: i64 = conn
            .pragma_query_value(None, "journal_size_limit", |r| r.get(0))
            .expect("journal_size_limit");
        assert_eq!(journal_size_limit, 67_108_864);
    }

    #[test]
    fn schema_version_pack_unpack_roundtrips_without_collision() {
        assert_eq!(unpack_schema_versions(0), (0, 0));
        assert_eq!(unpack_schema_versions(-1), (0, 0));
        assert_eq!(unpack_schema_versions(i32::MIN), (0, 0));

        let packed = pack_schema_versions(3, 5);
        assert_eq!(packed, (3 << 16) | 5);
        assert_eq!(unpack_schema_versions(packed), (3, 5));

        // Tenant version masks to 15 bits so packed user_version stays non-negative.
        let masked = pack_schema_versions(0xFFFF, 42);
        assert!(masked >= 0);
        assert_eq!(unpack_schema_versions(masked), (0x7FFF, 42));
    }

    #[test]
    fn require_non_empty_did_trims_valid_and_rejects_blank() {
        assert_eq!(
            require_non_empty_did("did:plc:alice", "tenant_did").unwrap(),
            "did:plc:alice"
        );
        assert_eq!(
            require_non_empty_did("  did:plc:alice\t\n ", "tenant_did").unwrap(),
            "did:plc:alice"
        );

        let err_empty = require_non_empty_did("", "tenant_did").unwrap_err();
        assert!(
            matches!(err_empty, crate::error::SkybouncerError::Config(ref msg) if msg == "tenant_did cannot be empty"),
            "unexpected error for empty DID: {err_empty:?}"
        );

        let err_ws = require_non_empty_did("   \t\n ", "protected_did").unwrap_err();
        assert!(
            matches!(err_ws, crate::error::SkybouncerError::Config(ref msg) if msg == "protected_did cannot be empty"),
            "unexpected error for whitespace DID: {err_ws:?}"
        );
    }

    #[test]
    fn is_pds_record_not_found_matches_each_known_pds_error_independently() {
        assert!(is_pds_record_not_found("CouldNotFindRecord"));
        assert!(is_pds_record_not_found(
            r#"XRPC error 400: {"error":"CouldNotFindRecord","message":"missing"}"#
        ));

        assert!(is_pds_record_not_found("RecordNotFound"));
        assert!(is_pds_record_not_found(
            r#"XRPC error 400: {"error":"RecordNotFound","message":"missing"}"#
        ));

        assert!(is_pds_record_not_found("Could not locate record"));
        assert!(is_pds_record_not_found(
            "PDS error: Could not locate record at://did:plc:alice/app.bsky.graph.list/3k"
        ));

        assert!(is_pds_record_not_found("Could not find record"));
        assert!(is_pds_record_not_found(
            "PDS error: Could not find record for rkey 3k"
        ));
    }

    #[test]
    fn is_pds_record_not_found_rejects_unrelated_and_raw_404_errors() {
        assert!(!is_pds_record_not_found(""));
        assert!(!is_pds_record_not_found("HTTP 404 Not Found"));
        assert!(!is_pds_record_not_found(
            "<html><body>404 Not Found</body></html>"
        ));
        assert!(!is_pds_record_not_found("InternalServerError"));
        assert!(!is_pds_record_not_found("InvalidSwap"));
    }
}
