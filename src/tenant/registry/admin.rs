use super::*;

impl TenantRegistry {
    pub(super) fn map_tenant_meta_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TenantMeta> {
        let did: String = row.get(0)?;
        let handle: Option<String> = row.get(1)?;
        let has_session: bool = row.get::<_, i64>(2)? != 0;
        let reauth_required: bool = row.get::<_, i64>(3)? != 0;
        let rubric_prompt: Option<String> = row.get(4)?;
        let sensitivity_str: Option<String> = row.get(5)?;
        let bounce_duration_str: Option<String> = row.get(6)?;
        let bypass_followers_int: Option<i64> = row.get(7)?;
        let is_active: bool = row.get::<_, i64>(8)? != 0;
        let created_at = i64_to_us(row.get(9)?);
        let updated_at = i64_to_us(row.get(10)?);

        let rubric = Self::decode_rubric_fields(
            rubric_prompt,
            sensitivity_str,
            bounce_duration_str,
            bypass_followers_int,
        );

        Ok(TenantMeta {
            did,
            handle,
            rubric,
            is_active,
            reauth_required,
            has_session,
            created_at,
            updated_at,
        })
    }

    pub(super) fn query_meta_locked(
        conn: &Connection,
        did: &str,
    ) -> Result<Option<TenantMeta>, SkybouncerError> {
        let mut stmt = conn.prepare_cached(
            "SELECT did, handle,
                    (session_json IS NOT NULL AND TRIM(session_json) != '') AS has_session,
                    reauth_required, rubric_prompt, sensitivity, bounce_duration,
                    bypass_followers, is_active, created_at, updated_at
             FROM tenants
             WHERE did = ?1;",
        )?;
        Ok(stmt
            .query_row(params![did], Self::map_tenant_meta_row)
            .optional()?)
    }

    /// Retrieves cached lightweight metadata for `did`, falling back to a projection-only
    /// SQLite lookup (without decrypting `session_json`) on cache miss.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_meta(&self, did: &str) -> Result<Option<TenantMeta>, SkybouncerError> {
        if let Some(cached) = self.meta_cache.read().get(did).cloned() {
            return Ok(Some(cached));
        }

        let fetched = {
            let conn = self.conn.lock();
            Self::query_meta_locked(&conn, did)?
        };

        if let Some(ref meta) = fetched {
            self.meta_cache
                .write()
                .insert(meta.did.clone(), meta.clone());
        }
        Ok(fetched)
    }

    /// Returns lightweight activation and re-auth status for `did` via `meta_cache` / SQL projection
    /// without decrypting `session_json`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_status(&self, did: &str) -> Result<Option<TenantStatus>, SkybouncerError> {
        Ok(self.get_meta(did)?.map(|m| TenantStatus {
            is_active: m.is_active,
            reauth_required: m.reauth_required,
        }))
    }

    /// Returns the tenant's configured moderation rubric via `meta_cache` / SQL projection
    /// without decrypting `session_json`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_rubric(&self, did: &str) -> Result<Option<RuleRubric>, SkybouncerError> {
        Ok(self.get_meta(did)?.and_then(|m| m.rubric))
    }

    /// Returns the tenant's cached handle via `meta_cache` / SQL projection
    /// without decrypting `session_json`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_handle(&self, did: &str) -> Result<Option<String>, SkybouncerError> {
        Ok(self.get_meta(did)?.and_then(|m| m.handle))
    }

    /// Lists lightweight metadata summaries for all enrolled tenants in a single SQL query
    /// without decrypting `session_json` or parsing DPoP keys, and refreshes `meta_cache`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn list_summaries(&self) -> Result<Vec<TenantSummary>, SkybouncerError> {
        let summaries = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT did, handle,
                        (session_json IS NOT NULL AND TRIM(session_json) != '') AS has_session,
                        reauth_required, rubric_prompt, sensitivity, bounce_duration,
                        bypass_followers, is_active, created_at, updated_at
                 FROM tenants
                 ORDER BY created_at ASC;",
            )?;
            let rows = stmt.query_map([], Self::map_tenant_meta_row)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            out
        };

        {
            let mut cache = self.meta_cache.write();
            cache.clear();
            for meta in &summaries {
                cache.insert(meta.did.clone(), meta.clone());
            }
        }
        Ok(summaries)
    }

    /// Checks whether the given DID is registered and enrolled in the tenant registry.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn is_enrolled(&self, did: &str) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT 1 FROM tenants WHERE did = ?1 LIMIT 1;")?;
        let exists = stmt
            .query_row(params![did], |_| Ok(()))
            .optional()?
            .is_some();
        Ok(exists)
    }

    /// Lists all enrolled tenants whose automated moderation status is active (`is_active = 1`).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if query fails.
    pub fn list_active(&self) -> Result<Vec<Tenant>, SkybouncerError> {
        self.list_filtered(true)
    }

    /// Lists all enrolled tenants regardless of active status.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if query fails.
    pub fn list_all(&self) -> Result<Vec<Tenant>, SkybouncerError> {
        self.list_filtered(false)
    }

    /// Lists enrolled tenants, optionally restricted to active ones.
    pub(super) fn list_filtered(&self, active_only: bool) -> Result<Vec<Tenant>, SkybouncerError> {
        let dids = {
            let conn = self.conn.lock();
            let query = if active_only {
                "SELECT did FROM tenants WHERE is_active = 1 ORDER BY created_at ASC;"
            } else {
                "SELECT did FROM tenants ORDER BY created_at ASC;"
            };
            let mut stmt = conn.prepare_cached(query)?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut dids = Vec::new();
            for r in rows {
                dids.push(r?);
            }
            dids
        };

        let mut tenants = Vec::with_capacity(dids.len());
        for did in dids {
            if let Some(t) = self.get(&did)? {
                tenants.push(t);
            }
        }
        Ok(tenants)
    }

    /// Toggles the active status (`is_active`) of an enrolled tenant.
    ///
    /// Returns `true` if the tenant was found and updated.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if update query fails.
    pub fn set_active(&self, did: &str, is_active: bool) -> Result<bool, SkybouncerError> {
        let is_active_int: i64 = if is_active { 1 } else { 0 };
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);

        let count = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "UPDATE tenants SET is_active = ?1, updated_at = ?2 WHERE did = ?3;",
            )?;
            stmt.execute(params![is_active_int, now_i64, did])?
        };
        if count > 0 {
            if let Some(entry) = self.meta_cache.write().get_mut(did) {
                entry.is_active = is_active;
                entry.updated_at = now_us;
            }
        }
        Ok(count > 0)
    }

    /// Updates the custom rule rubric for an enrolled tenant.
    ///
    /// Returns `true` if the tenant was found and updated.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if update query fails.
    pub fn update_rubric(&self, did: &str, rubric: &RuleRubric) -> Result<bool, SkybouncerError> {
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);

        let count = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "UPDATE tenants SET rubric_prompt = ?1, sensitivity = ?2, bounce_duration = ?3, bypass_followers = ?4, updated_at = ?5 WHERE did = ?6;",
            )?;
            stmt.execute(params![
                rubric.prompt,
                rubric.sensitivity.to_string(),
                rubric.bounce_duration.to_db_string(),
                i64::from(rubric.bypass_incoming_followers),
                now_i64,
                did
            ])?
        };
        if count > 0 {
            if let Some(entry) = self.meta_cache.write().get_mut(did) {
                entry.rubric = Some(rubric.clone());
                entry.updated_at = now_us;
            }
        }
        Ok(count > 0)
    }

    /// Deletes a tenant and all of their web sessions atomically from the registry.
    ///
    /// Returns `true` if the tenant was found and deleted.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if deletion fails.
    pub fn remove(&self, did: &str) -> Result<bool, SkybouncerError> {
        let count = {
            let mut conn = self.conn.lock();
            let tx = conn.transaction()?;
            tx.execute("DELETE FROM web_sessions WHERE did = ?1;", params![did])?;
            let count = tx.execute("DELETE FROM tenants WHERE did = ?1;", params![did])?;
            tx.commit()?;
            count
        };
        self.meta_cache.write().remove(did);
        self.bump_epoch_and_evict(did);
        Ok(count > 0)
    }
}
