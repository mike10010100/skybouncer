use super::*;

impl SkybouncerEngine {
    /// Resolves an ATProto handle to a DID using in-memory monotonic caching,
    /// tenant registry handle-mapping TTL caching, the persisted SQLite handle
    /// cache, and the configured context enricher.
    ///
    /// If the provided handle is already a DID (starts with `did:`), it is returned directly.
    pub async fn resolve_handle(&self, handle: &str) -> Option<String> {
        let clean = crate::util::normalize_handle(handle);
        if clean.starts_with("did:") {
            return Some(clean.to_string());
        }
        let now = std::time::Instant::now();

        // 1. In-memory monotonic check
        {
            let guard = self.handle_cache.read();
            if let Some((did, cached_at)) = guard.get(clean) {
                if now.saturating_duration_since(*cached_at) < self.config.handle_cache_ttl {
                    return Some(did.clone());
                }
            }
        }

        // 2. Tenant registry check with handle-mapping TTL
        if let Ok(Some(tenant)) = self
            .tenant_registry
            .get_by_handle_with_ttl(clean, self.config.handle_cache_ttl)
        {
            let _ = self.cache.set_handle_for_did(&tenant.did, clean);
            self.handle_cache
                .write()
                .insert(clean.to_string(), (tenant.did.clone(), now));
            return Some(tenant.did);
        }

        // 3. Persisted SQLite did_handles cache (TTL-bounded to avoid identity shadowing)
        let ttl_us = u64::try_from(self.config.handle_cache_ttl.as_micros()).unwrap_or(u64::MAX);
        if let Ok(Some(cached_did)) = self.cache.get_did_for_handle_with_ttl(clean, ttl_us) {
            self.handle_cache
                .write()
                .insert(clean.to_string(), (cached_did.clone(), now));
            return Some(cached_did);
        }

        // 4. Remote AppView resolution via enricher
        if let Some(live_did) = self.enricher.resolve_handle(clean).await {
            let _ = self.cache.set_handle_for_did(&live_did, clean);
            self.handle_cache
                .write()
                .insert(clean.to_string(), (live_did.clone(), now));
            return Some(live_did);
        }

        None
    }

    /// Invalidates a handle across the in-memory cache, the tenant registry, and
    /// the persisted SQLite handle cache.
    pub fn invalidate_handle(&self, handle: &str) {
        let clean = crate::util::normalize_handle(handle);
        self.handle_cache.write().remove(clean);
        let _ = self.tenant_registry.invalidate_handle(clean);
        let _ = self.cache.remove_handle_for_handle(clean);
    }

    /// Clears all entries from the in-memory handle cache.
    pub fn clear_handle_cache(&self) {
        self.handle_cache.write().clear();
    }

    /// Resolves an ATProto DID to a handle using only local caches (tenant registry and SQLite).
    ///
    /// This never performs network I/O and is intended for enriching list responses where
    /// outbound resolution would otherwise cause an N+1 fan-out of remote lookups.
    #[must_use]
    pub fn cached_handle_for_did(&self, did: &str) -> Option<String> {
        let clean = did.trim();
        if !clean.starts_with("did:") {
            return None;
        }

        // 1. Check local tenant cache
        if let Ok(Some(tenant)) = self.tenant_registry.get(clean) {
            if let Some(handle) = tenant.handle {
                let trimmed = crate::util::normalize_handle(&handle).to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }

        // 2. Check SQLite did_handles cache
        if let Ok(Some(cached_handle)) = self.cache.get_handle_for_did(clean) {
            let trimmed = crate::util::normalize_handle(&cached_handle).to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }

        None
    }

    /// Resolves an ATProto DID to a handle using cached tenant data, local handle cache, or the configured context enricher.
    ///
    /// If the handle was not already cached in the local tenant registry and is successfully resolved
    /// via the enricher, it is automatically cached into SQLite for future instant retrieval.
    pub async fn resolve_did_to_handle(&self, did: &str) -> Option<String> {
        let clean = did.trim();
        if !clean.starts_with("did:") {
            return None;
        }

        if let Some(cached) = self.cached_handle_for_did(clean) {
            return Some(cached);
        }

        // Resolve via enricher
        if let Some(resolved) = self.enricher.resolve_did(clean).await {
            let trimmed = crate::util::normalize_handle(&resolved).to_string();
            if !trimmed.is_empty() {
                let _ = self.cache.set_handle_for_did(clean, &trimmed);
                let _ = self.tenant_registry.update_handle(clean, &trimmed);
                return Some(trimmed);
            }
        }

        None
    }

    /// Returns the resolved handle for a protected user DID, or an empty string if unknown.
    #[must_use]
    pub fn target_handle(&self, did: &str) -> String {
        self.tenant_registry
            .get(did)
            .ok()
            .flatten()
            .and_then(|t| t.handle)
            .unwrap_or_default()
    }
}
