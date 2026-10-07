use super::*;

impl DeduplicationCache {
    /// Adds an account to the protected user's moderation allowlist.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite persistence fails.
    pub fn add_to_allowlist(
        &self,
        protected_did: &str,
        subject_did: &str,
        reason: Option<&str>,
    ) -> Result<(), SkybouncerError> {
        let conn = self.conn.lock();
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);

        let mut stmt = conn.prepare_cached(
            "INSERT INTO allowlist (protected_did, subject_did, reason, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(protected_did, subject_did) DO UPDATE SET
                 reason = excluded.reason,
                 created_at = excluded.created_at;",
        )?;

        stmt.execute(params![protected_did, subject_did, reason, now_i64])?;
        Ok(())
    }

    /// Removes an account from the protected user's moderation allowlist.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite delete fails.
    pub fn remove_from_allowlist(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "DELETE FROM allowlist WHERE protected_did = ?1 AND subject_did = ?2;",
        )?;
        let affected = stmt.execute(params![protected_did, subject_did])?;
        Ok(affected > 0)
    }

    /// Checks whether an account is currently on the protected user's moderation allowlist in SQLite.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn is_allowlisted(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT 1 FROM allowlist WHERE protected_did = ?1 AND subject_did = ?2 LIMIT 1;",
        )?;
        let exists = stmt
            .query_row(params![protected_did, subject_did], |_| Ok(()))
            .optional()?
            .is_some();
        Ok(exists)
    }

    /// Lists all accounts on the protected user's moderation allowlist.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn list_allowlist(
        &self,
        protected_did: &str,
    ) -> Result<Vec<AllowlistEntry>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT a.protected_did, a.subject_did, a.reason, a.created_at, h.handle
             FROM allowlist a
             LEFT JOIN did_handles h ON a.subject_did = h.did
             WHERE a.protected_did = ?1
             ORDER BY a.created_at DESC;",
        )?;
        let rows = stmt.query_map(params![protected_did], |row| {
            let p_did: String = row.get(0)?;
            let s_did: String = row.get(1)?;
            let reason: Option<String> = row.get(2)?;
            let created_at_i64: i64 = row.get(3)?;
            let created_at = i64_to_us(created_at_i64);
            let handle: Option<String> = row.get(4)?;
            Ok(AllowlistEntry {
                protected_did: p_did,
                subject_did: s_did,
                handle,
                reason,
                created_at,
            })
        })?;

        let mut entries = Vec::new();
        for r in rows {
            entries.push(r?);
        }
        Ok(entries)
    }

    /// Loads all allowlist records across all protected users into a nested HashMap.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn load_all_allowlists(&self) -> Result<HashMap<String, HashSet<String>>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT protected_did, subject_did FROM allowlist;")?;
        let rows = stmt.query_map([], |row| {
            let p_did: String = row.get(0)?;
            let s_did: String = row.get(1)?;
            Ok((p_did, s_did))
        })?;

        let mut map: HashMap<String, HashSet<String>> = HashMap::new();
        for r in rows {
            let (p, s) = r?;
            map.entry(p).or_default().insert(s);
        }
        Ok(map)
    }
}
