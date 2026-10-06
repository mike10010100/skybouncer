use super::*;

impl DeduplicationCache {
    /// Checks whether the subject DID is already recorded as bounced.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn is_bounced(&self, subject_did: &str) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("SELECT 1 FROM bounced_users WHERE subject_did = ?1 LIMIT 1;")?;

        let exists = stmt
            .query_row(params![subject_did], |_| Ok(()))
            .optional()?
            .is_some();

        Ok(exists)
    }

    /// Checks whether a subject DID is recorded as bounced for a specific protected user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn is_bounced_for(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT 1 FROM bounced_users
             WHERE subject_did = ?1 AND protected_did = ?2 LIMIT 1;",
        )?;

        let exists = stmt
            .query_row(params![subject_did, protected_did], |_| Ok(()))
            .optional()?
            .is_some();

        Ok(exists)
    }

    /// Retrieves detailed record of a bounced violator if present.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn get_bounced_user(
        &self,
        subject_did: &str,
    ) -> Result<Option<BouncedUser>, SkybouncerError> {
        self.get_bounced_user_scoped(None, subject_did)
    }

    /// Retrieves detailed record of a bounced violator for a specific protected user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn get_bounced_user_for(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<Option<BouncedUser>, SkybouncerError> {
        self.get_bounced_user_scoped(Some(protected_did), subject_did)
    }

    /// Retrieves a bounce record optionally scoped to a specific protected user.
    pub(super) fn get_bounced_user_scoped(
        &self,
        protected_did: Option<&str>,
        subject_did: &str,
    ) -> Result<Option<BouncedUser>, SkybouncerError> {
        let conn = self.conn.lock();
        let res = match protected_did.filter(|s| !s.trim().is_empty()) {
            Some(target) => {
                let mut stmt = conn.prepare_cached(&format!(
                    "SELECT {BOUNCED_USER_COLUMNS}
                     FROM bounced_users
                     WHERE subject_did = ?1 AND protected_did = ?2;"
                ))?;
                stmt.query_row(params![subject_did, target], map_bounced_user)
                    .optional()?
            }
            None => {
                let mut stmt = conn.prepare_cached(&format!(
                    "SELECT {BOUNCED_USER_COLUMNS}
                     FROM bounced_users
                     WHERE subject_did = ?1
                     LIMIT 1;"
                ))?;
                stmt.query_row(params![subject_did], map_bounced_user)
                    .optional()?
            }
        };
        Ok(res)
    }

    /// Records a bounced violator and their corresponding PDS listitem record into the cache.
    ///
    /// Preserves all historical and concurrent `listitem_rkey` values in `bounced_user_rkeys`
    /// while maintaining the canonical latest bounce state in `bounced_users`.
    ///
    /// Uses a single SQLite transaction to guarantee atomicity.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the insert fails.
    pub fn record_bounce(&self, entry: &BouncedUser) -> Result<(), SkybouncerError> {
        let bounced_at_i64 = us_to_i64(entry.bounced_at);
        let expires_at_i64 = entry.expires_at.map(us_to_i64);

        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(|e| {
            SkybouncerError::Database(format!(
                "Failed to start transaction for bounce record: {e}"
            ))
        })?;

        // 1. Insert or update the canonical bounced_users record
        {
            let mut user_stmt = tx.prepare_cached(
                "INSERT INTO bounced_users (
                        subject_did, listitem_uri, listitem_rkey, listitem_cid,
                        category, confidence, reason, post_uri, bounced_at,
                        protected_did, post_text, expires_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                     ON CONFLICT(protected_did, subject_did) DO UPDATE SET
                         listitem_uri = excluded.listitem_uri,
                         listitem_rkey = excluded.listitem_rkey,
                         listitem_cid = excluded.listitem_cid,
                         category = excluded.category,
                         confidence = excluded.confidence,
                         reason = excluded.reason,
                         post_uri = excluded.post_uri,
                         bounced_at = excluded.bounced_at,
                         post_text = excluded.post_text,
                         expires_at = excluded.expires_at;",
            )?;

            user_stmt.execute(params![
                entry.subject_did,
                entry.listitem_uri,
                entry.listitem_rkey,
                entry.listitem_cid,
                entry.category,
                entry.confidence,
                entry.reason,
                entry.post_uri,
                bounced_at_i64,
                entry.protected_did,
                entry.post_text,
                expires_at_i64,
            ])?;
        }

        // 2. Record in historical rkeys table (never overwrites or erases existing rkeys)
        {
            let mut rkey_stmt = tx.prepare_cached(
                "INSERT INTO bounced_user_rkeys (
                    protected_did, subject_did, listitem_rkey, listitem_uri, listitem_cid, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(listitem_rkey) DO NOTHING;",
            )?;

            rkey_stmt.execute(params![
                entry.protected_did,
                entry.subject_did,
                entry.listitem_rkey,
                entry.listitem_uri,
                entry.listitem_cid,
                bounced_at_i64,
            ])?;
        }

        tx.commit().map_err(|e| {
            SkybouncerError::Database(format!("Failed to commit bounce record transaction: {e}"))
        })?;

        Ok(())
    }

    /// Retrieves all known listitem `rkey` values associated with the given subject DID for a protected user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn get_all_bounced_rkeys_for(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<Vec<String>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut rkeys = Vec::new();
        let mut seen = std::collections::HashSet::new();

        if protected_did.is_empty() {
            let mut stmt = conn.prepare_cached(
                "SELECT listitem_rkey FROM bounced_user_rkeys
                 WHERE subject_did = ?1
                 ORDER BY created_at ASC;",
            )?;

            let rows = stmt.query_map(params![subject_did], |row| row.get::<_, String>(0))?;
            for r in rows {
                let rk = r?;
                if seen.insert(rk.clone()) {
                    rkeys.push(rk);
                }
            }

            if rkeys.is_empty() {
                let mut fallback_stmt = conn.prepare_cached(
                    "SELECT listitem_rkey FROM bounced_users WHERE subject_did = ?1;",
                )?;
                let fallback_rkey: Option<String> = fallback_stmt
                    .query_row(params![subject_did], |row| row.get(0))
                    .optional()?;
                if let Some(rk) = fallback_rkey {
                    rkeys.push(rk);
                }
            }
        } else {
            let mut stmt = conn.prepare_cached(
                "SELECT listitem_rkey FROM bounced_user_rkeys
                 WHERE subject_did = ?1 AND protected_did = ?2
                 ORDER BY created_at ASC;",
            )?;

            let rows = stmt.query_map(params![subject_did, protected_did], |row| {
                row.get::<_, String>(0)
            })?;
            for r in rows {
                let rk = r?;
                if seen.insert(rk.clone()) {
                    rkeys.push(rk);
                }
            }

            if rkeys.is_empty() {
                let mut fallback_stmt = conn.prepare_cached(
                    "SELECT listitem_rkey FROM bounced_users WHERE subject_did = ?1 AND protected_did = ?2;",
                )?;
                let fallback_rkey: Option<String> = fallback_stmt
                    .query_row(params![subject_did, protected_did], |row| row.get(0))
                    .optional()?;
                if let Some(rk) = fallback_rkey {
                    rkeys.push(rk);
                }
            }
        }

        Ok(rkeys)
    }

    /// Retrieves all known listitem `rkey` values associated with the given subject DID across all lists.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn get_all_bounced_rkeys(&self, subject_did: &str) -> Result<Vec<String>, SkybouncerError> {
        self.get_all_bounced_rkeys_for("", subject_did)
    }

    /// Retrieves all known listitem `rkey` values associated with the given subject DID.
    ///
    /// Alias for [`Self::get_all_bounced_rkeys`].
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn get_bounced_rkeys(&self, subject_did: &str) -> Result<Vec<String>, SkybouncerError> {
        self.get_all_bounced_rkeys(subject_did)
    }

    /// Lists recently bounced users ordered by most recent bounce timestamp descending.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn list_recent_bounces(&self, limit: usize) -> Result<Vec<BouncedUser>, SkybouncerError> {
        self.list_recent_bounces_for(None, limit)
    }

    /// Lists recently bounced users filtered by an optional protected user DID,
    /// ordered by most recent bounce timestamp descending.
    ///
    /// Strictly isolates tenant moderation data: when `protected_did` is provided,
    /// only bounces for that exact tenant are returned.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn list_recent_bounces_for(
        &self,
        protected_did: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BouncedUser>, SkybouncerError> {
        let limit_i64 = i64::try_from(limit).unwrap_or(50);
        let conn = self.conn.lock();
        let mut list = Vec::new();

        if let Some(target) = protected_did.filter(|s| !s.trim().is_empty()) {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {BOUNCED_USER_COLUMNS}
                 FROM bounced_users
                 WHERE protected_did = ?1
                 ORDER BY bounced_at DESC
                 LIMIT ?2;"
            ))?;

            let rows = stmt.query_map(params![target, limit_i64], map_bounced_user)?;

            for r in rows {
                list.push(r?);
            }
        } else {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {BOUNCED_USER_COLUMNS}
                 FROM bounced_users
                 ORDER BY bounced_at DESC
                 LIMIT ?1;"
            ))?;

            let rows = stmt.query_map(params![limit_i64], map_bounced_user)?;

            for r in rows {
                list.push(r?);
            }
        }

        Ok(list)
    }

    /// Lists all temporary bounces that have expired relative to `now_us`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn list_expired_bounces(&self, now_us: u64) -> Result<Vec<BouncedUser>, SkybouncerError> {
        let now_i64 = us_to_i64(now_us);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {BOUNCED_USER_COLUMNS}
             FROM bounced_users
             WHERE expires_at IS NOT NULL AND expires_at <= ?1
             ORDER BY expires_at ASC;"
        ))?;

        let rows = stmt.query_map(params![now_i64], map_bounced_user)?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Removes a bounced user from the cache for a specific protected user, returning the listitem `rkey`.
    ///
    /// Cleans up both `bounced_users` and all associated entries in `bounced_user_rkeys`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query or deletion fails.
    pub fn remove_bounce_for(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<Option<String>, SkybouncerError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(|e| {
            SkybouncerError::Database(format!(
                "Failed to start transaction for remove_bounce: {e}"
            ))
        })?;

        let rkey: Option<String> = {
            if protected_did.is_empty() {
                let mut select_stmt = tx.prepare_cached(
                    "SELECT listitem_rkey FROM bounced_users WHERE subject_did = ?1 LIMIT 1;",
                )?;
                select_stmt
                    .query_row(params![subject_did], |row| row.get(0))
                    .optional()?
            } else {
                let mut select_stmt = tx.prepare_cached(
                    "SELECT listitem_rkey FROM bounced_users WHERE subject_did = ?1 AND protected_did = ?2 LIMIT 1;",
                )?;
                select_stmt
                    .query_row(params![subject_did, protected_did], |row| row.get(0))
                    .optional()?
            }
        };

        if rkey.is_some() {
            delete_bounce_rows(&tx, protected_did, subject_did)?;
        }

        tx.commit().map_err(|e| {
            SkybouncerError::Database(format!("Failed to commit remove_bounce transaction: {e}"))
        })?;

        Ok(rkey)
    }

    /// Removes a bounced user from the cache across all lists, returning the primary listitem `rkey`.
    ///
    /// Cleans up both `bounced_users` and all associated entries in `bounced_user_rkeys`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query or deletion fails.
    pub fn remove_bounce(&self, subject_did: &str) -> Result<Option<String>, SkybouncerError> {
        self.remove_bounce_for("", subject_did)
    }

    /// Removes a bounced user from the cache for a specific protected user, returning all known listitem `rkey` values.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query or deletion fails.
    pub fn remove_all_bounces_for(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<Vec<String>, SkybouncerError> {
        let rkeys = self.get_all_bounced_rkeys_for(protected_did, subject_did)?;
        if !rkeys.is_empty() {
            let mut conn = self.conn.lock();
            let tx = conn.transaction().map_err(|e| {
                SkybouncerError::Database(format!(
                    "Failed to start transaction for remove_all_bounces: {e}"
                ))
            })?;

            delete_bounce_rows(&tx, protected_did, subject_did)?;

            tx.commit().map_err(|e| {
                SkybouncerError::Database(format!(
                    "Failed to commit remove_all_bounces transaction: {e}"
                ))
            })?;
        }
        Ok(rkeys)
    }

    /// Removes a bounced user from the cache across all lists, returning all known listitem `rkey` values.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query or deletion fails.
    pub fn remove_all_bounces(&self, subject_did: &str) -> Result<Vec<String>, SkybouncerError> {
        self.remove_all_bounces_for("", subject_did)
    }

    /// Counts the total number of bounced users recorded in the cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn count_bounced(&self) -> Result<usize, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT COUNT(*) FROM bounced_users;")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(usize::try_from(count.max(0)).unwrap_or(0))
    }
}
