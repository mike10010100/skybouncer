use super::*;

impl TenantRegistry {
    /// Retrieves an enrolled tenant by Bluesky handle enforcing a maximum TTL age.
    ///
    /// Freshness is measured against the dedicated `handle_updated_at` column, which is
    /// advanced only when the handle mapping itself changes (registration, handle update,
    /// or explicit invalidation) — never by unrelated writes such as session token refreshes.
    /// This ensures a stale handle mapping cannot be kept "fresh" by background activity.
    ///
    /// The tenant's handle mapping must have been updated within `max_age` of the current time.
    /// If the handle mapping has expired or does not match, returns `Ok(None)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite lookup fails.
    pub fn get_by_handle_with_ttl(
        &self,
        handle: &str,
        max_age: Duration,
    ) -> Result<Option<Tenant>, SkybouncerError> {
        let clean = crate::util::normalize_handle(handle);
        let max_age_us = u64::try_from(max_age.as_micros()).unwrap_or(u64::MAX);
        let cutoff_us = current_time_us().saturating_sub(max_age_us);
        let cutoff_i64 = us_to_i64(cutoff_us);

        let did_opt: Option<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT did FROM tenants WHERE (LOWER(handle) = LOWER(?1) OR LOWER(handle) = LOWER(?2))
                 AND handle_updated_at IS NOT NULL AND handle_updated_at >= ?3 LIMIT 1;",
            )?;
            stmt.query_row(params![clean, format!("@{clean}"), cutoff_i64], |row| {
                row.get(0)
            })
            .optional()?
        };

        match did_opt {
            Some(did) => self.get(&did),
            None => Ok(None),
        }
    }

    /// Retrieves an enrolled tenant by Bluesky handle using the default TTL ([`DEFAULT_HANDLE_TTL`]).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite lookup fails.
    pub fn get_by_handle(&self, handle: &str) -> Result<Option<Tenant>, SkybouncerError> {
        self.get_by_handle_with_ttl(handle, DEFAULT_HANDLE_TTL)
    }

    /// Invalidates a handle mapping in the registry by setting `handle = NULL`
    /// for any matching tenants.
    ///
    /// Returns `true` if any tenant's handle was invalidated.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite update query fails.
    pub fn invalidate_handle(&self, handle: &str) -> Result<bool, SkybouncerError> {
        let clean = crate::util::normalize_handle(handle);
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "UPDATE tenants SET handle = NULL, handle_updated_at = ?1, updated_at = ?1
             WHERE LOWER(handle) = LOWER(?2) OR LOWER(handle) = LOWER(?3);",
        )?;
        let count = stmt.execute(params![now_i64, clean, format!("@{clean}")])?;
        Ok(count > 0)
    }

    /// Updates the handle for an enrolled tenant.
    ///
    /// Returns `true` if the tenant was found and updated.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if update query fails.
    pub fn update_handle(&self, did: &str, handle: &str) -> Result<bool, SkybouncerError> {
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "UPDATE tenants SET handle = ?1, handle_updated_at = ?2, updated_at = ?2 WHERE did = ?3;",
        )?;

        let count = stmt.execute(params![handle, now_i64, did])?;
        Ok(count > 0)
    }
}
