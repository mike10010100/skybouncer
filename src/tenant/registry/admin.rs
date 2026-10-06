use super::*;

impl TenantRegistry {
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

        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached("UPDATE tenants SET is_active = ?1, updated_at = ?2 WHERE did = ?3;")?;

        let count = stmt.execute(params![is_active_int, now_i64, did])?;
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

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "UPDATE tenants SET rubric_prompt = ?1, sensitivity = ?2, bounce_duration = ?3, bypass_followers = ?4, updated_at = ?5 WHERE did = ?6;",
        )?;

        let count = stmt.execute(params![
            rubric.prompt,
            rubric.sensitivity.to_string(),
            rubric.bounce_duration.to_db_string(),
            i64::from(rubric.bypass_incoming_followers),
            now_i64,
            did
        ])?;
        Ok(count > 0)
    }

    /// Deletes a tenant from the registry.
    ///
    /// Returns `true` if the tenant was found and deleted.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if deletion fails.
    pub fn remove(&self, did: &str) -> Result<bool, SkybouncerError> {
        self.pds_clients.write().remove(did);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("DELETE FROM tenants WHERE did = ?1;")?;
        let count = stmt.execute(params![did])?;
        Ok(count > 0)
    }
}
