use super::*;

impl DeduplicationCache {
    /// Looks up the cached handle for a given DID from SQLite.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_handle_for_did(&self, did: &str) -> Result<Option<String>, SkybouncerError> {
        let conn = self.conn.lock();
        let clean = did.trim();
        let mut stmt =
            conn.prepare_cached("SELECT handle FROM did_handles WHERE did = ?1 LIMIT 1;")?;
        let handle = stmt
            .query_row(params![clean], |row| row.get(0))
            .optional()?;
        Ok(handle)
    }

    /// Looks up the cached DID for a given handle from SQLite.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_did_for_handle(&self, handle: &str) -> Result<Option<String>, SkybouncerError> {
        let clean = crate::util::normalize_handle(handle);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT did FROM did_handles WHERE handle = ?1 COLLATE NOCASE LIMIT 1;",
        )?;
        let did = stmt
            .query_row(params![clean], |row| row.get(0))
            .optional()?;
        Ok(did)
    }

    /// Looks up the cached DID for a handle, ignoring mappings older than `max_age_us`
    /// microseconds.
    ///
    /// This prevents a stale persisted mapping from shadowing a handle that has since
    /// rotated to a new owner on the network.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_did_for_handle_with_ttl(
        &self,
        handle: &str,
        max_age_us: u64,
    ) -> Result<Option<String>, SkybouncerError> {
        let clean = crate::util::normalize_handle(handle);
        let cutoff_i64 = us_to_i64(current_time_us().saturating_sub(max_age_us));
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT did FROM did_handles WHERE handle = ?1 COLLATE NOCASE AND updated_at >= ?2 LIMIT 1;",
        )?;
        let did = stmt
            .query_row(params![clean, cutoff_i64], |row| row.get(0))
            .optional()?;
        Ok(did)
    }

    /// Caches a DID to handle mapping in SQLite.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite execution fails.
    pub fn set_handle_for_did(&self, did: &str, handle: &str) -> Result<(), SkybouncerError> {
        let clean_did = did.trim();
        let clean_handle = crate::util::normalize_handle(handle);
        if clean_did.is_empty() || clean_handle.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock();
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);
        let mut stmt = conn.prepare_cached(
            "INSERT INTO did_handles (did, handle, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(did) DO UPDATE SET handle = excluded.handle, updated_at = excluded.updated_at;",
        )?;
        stmt.execute(params![clean_did, clean_handle, now_i64])?;
        Ok(())
    }

    /// Removes the cached DID-to-handle mapping for a given handle.
    ///
    /// Used to invalidate a rotated or stale handle so subsequent lookups
    /// re-resolve it from the authoritative source.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite execution fails.
    pub fn remove_handle_for_handle(&self, handle: &str) -> Result<usize, SkybouncerError> {
        let clean = crate::util::normalize_handle(handle);
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("DELETE FROM did_handles WHERE handle = ?1 COLLATE NOCASE;")?;
        let deleted = stmt.execute(params![clean])?;
        Ok(deleted)
    }

    /// Prunes stale DID-to-handle cache entries and bounds the table size.
    ///
    /// First deletes mappings whose `updated_at` is strictly older than `older_than_us`,
    /// then, if more than `max_retained` rows remain, deletes the oldest mappings until
    /// only the `max_retained` most recently updated entries survive.
    ///
    /// Returns the total number of deleted rows.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite execution fails.
    pub fn prune_did_handles(
        &self,
        older_than_us: u64,
        max_retained: usize,
    ) -> Result<usize, SkybouncerError> {
        let conn = self.conn.lock();
        let cutoff_i64 = us_to_i64(older_than_us);
        let mut expire_stmt =
            conn.prepare_cached("DELETE FROM did_handles WHERE updated_at < ?1;")?;
        let mut deleted = expire_stmt.execute(params![cutoff_i64])?;

        let max_i64 = i64::try_from(max_retained.max(1)).unwrap_or(i64::MAX);
        let mut cap_stmt = conn.prepare_cached(
            "DELETE FROM did_handles WHERE did NOT IN (
                SELECT did FROM did_handles ORDER BY updated_at DESC LIMIT ?1
             );",
        )?;
        deleted = deleted.saturating_add(cap_stmt.execute(params![max_i64])?);
        Ok(deleted)
    }
}
