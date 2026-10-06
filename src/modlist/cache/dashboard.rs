use super::*;

impl DeduplicationCache {
    /// Persists a serialized dashboard telemetry snapshot for surviving process restarts.
    ///
    /// The snapshot is stored as a single well-known row (`id = 1`) and upserted atomically,
    /// so the latest write always wins without accumulating stale history.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] or [`SkybouncerError::Serialization`] if the
    /// snapshot cannot be serialized or persisted.
    pub fn save_dashboard_stats<T: Serialize + ?Sized>(
        &self,
        snapshot: &T,
    ) -> Result<(), SkybouncerError> {
        let snapshot_json = serde_json::to_string(snapshot)?;
        let now_us = us_to_i64(current_time_us());
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO dashboard_stats (id, snapshot_json, updated_at)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
                 snapshot_json = excluded.snapshot_json,
                 updated_at = excluded.updated_at;",
        )?;
        stmt.execute(params![snapshot_json, now_us])?;
        Ok(())
    }

    /// Loads the most recently persisted dashboard telemetry snapshot, if any.
    ///
    /// Returns `Ok(None)` when no snapshot has ever been saved or the stored payload cannot
    /// be deserialized (e.g. after a schema change), allowing callers to fall back to defaults.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn load_dashboard_stats<T: serde::de::DeserializeOwned>(
        &self,
    ) -> Result<Option<T>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("SELECT snapshot_json FROM dashboard_stats WHERE id = 1;")?;
        let raw: Option<String> = stmt.query_row([], |row| row.get(0)).optional()?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        match serde_json::from_str::<T>(&raw) {
            Ok(snapshot) => Ok(Some(snapshot)),
            Err(e) => {
                tracing::warn!(error = %e, "Discarding unreadable persisted dashboard telemetry snapshot");
                Ok(None)
            }
        }
    }
}
