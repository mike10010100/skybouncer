use super::*;

impl DeduplicationCache {
    /// Retrieves the provisioned moderation list configuration for the given protected user DID.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn get_mod_list(&self, user_did: &str) -> Result<Option<ModListConfig>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT user_did, list_uri, list_cid, created_at
                 FROM mod_list_config
                 WHERE user_did = ?1;",
        )?;

        let res = stmt
            .query_row(params![user_did], |row| {
                let created_at_i64: i64 = row.get(3)?;
                let created_at = i64_to_us(created_at_i64);
                Ok(ModListConfig {
                    user_did: row.get(0)?,
                    list_uri: row.get(1)?,
                    list_cid: row.get(2)?,
                    created_at,
                })
            })
            .optional()?;

        Ok(res)
    }

    /// Persists or updates the moderation list configuration for a protected user DID.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the insert fails.
    pub fn set_mod_list(&self, config: &ModListConfig) -> Result<(), SkybouncerError> {
        let created_at_i64 = us_to_i64(config.created_at);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO mod_list_config (user_did, list_uri, list_cid, created_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(user_did) DO UPDATE SET
                     list_uri = excluded.list_uri,
                     list_cid = excluded.list_cid,
                     created_at = excluded.created_at;",
        )?;

        stmt.execute(params![
            config.user_did,
            config.list_uri,
            config.list_cid,
            created_at_i64,
        ])?;

        Ok(())
    }

    /// Checks whether an automatic `app.bsky.graph.listblock` subscription is cached for the user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn is_list_blocked(&self, user_did: &str) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM listblock_cache WHERE user_did = ?1 LIMIT 1;")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to prepare listblock query: {e}"))
            })?;

        let exists = stmt
            .query_row(params![user_did], |_| Ok(()))
            .optional()
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to check listblock cache: {e}"))
            })?
            .is_some();

        Ok(exists)
    }

    /// Records an active `app.bsky.graph.listblock` subscription for the user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite execution fails.
    pub fn set_list_blocked(&self, user_did: &str, list_uri: &str) -> Result<(), SkybouncerError> {
        let now_us = current_time_us();
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO listblock_cache (user_did, list_uri, blocked_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(user_did) DO UPDATE SET
                 list_uri = excluded.list_uri,
                 blocked_at = excluded.blocked_at;",
        )?;

        stmt.execute(params![user_did, list_uri, now_us])?;
        Ok(())
    }
}
