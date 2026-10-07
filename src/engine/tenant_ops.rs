use super::*;

impl SkybouncerEngine {
    /// Enrolls or updates an active tenant in the registry and active watch set.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if tenant registration fails.
    pub fn enroll_tenant(&self, tenant: Tenant) -> Result<(), SkybouncerError> {
        let did = tenant.did.clone();
        self.tenant_registry.register_or_update(&tenant)?;
        self.add_protected_did(did);
        Ok(())
    }

    /// Checks whether a DID is an enrolled tenant in the registry.
    #[must_use]
    pub fn is_enrolled(&self, did: &str) -> bool {
        self.tenant_registry.is_enrolled(did).unwrap_or(false)
    }

    /// Checks whether the given DID has administrator privileges.
    #[must_use]
    pub fn is_admin(&self, did: &str) -> bool {
        let clean = did.trim();
        if clean.is_empty() {
            return false;
        }

        if let Some(ref admin) = self.config.admin_did {
            let admin_clean = admin.trim();
            if !admin_clean.is_empty() && admin_clean.eq_ignore_ascii_case(clean) {
                return true;
            }
        }

        false
    }

    /// Returns true if running in single-tenant mode (at most one protected DID besides admin, and no multi-tenant enrollments).
    #[must_use]
    pub fn is_single_tenant(&self) -> bool {
        if self.tenant_registry.count().unwrap_or(0) > 1 {
            return false;
        }
        let guard = self.protected_dids.read();
        let non_admin_count = guard.iter().filter(|d| !self.is_admin(d)).count();
        non_admin_count <= 1
    }

    /// Checks whether a tenant is paused (or the entire engine is paused).
    #[must_use]
    pub fn is_tenant_paused(&self, did: &str) -> bool {
        if self.is_paused() {
            return true;
        }
        match self.tenant_registry.get(did) {
            Ok(Some(tenant)) => !tenant.is_active,
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(did = %did, error = %e, "Failed to query tenant status; failing closed (paused)");
                true
            }
        }
    }

    /// Retrieves the moderation rubric for a specific protected user, falling back to engine default rubric.
    #[must_use]
    pub fn rubric_for(&self, did: &str) -> RuleRubric {
        if let Ok(Some(tenant)) = self.tenant_registry.get(did) {
            if let Some(rubric) = tenant.rubric {
                return rubric;
            }
        }
        self.rubric()
    }

    /// Resolves the [`PdsRepoClient`] for a specific protected user, failing closed if tenant resolution fails.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the tenant is enrolled but client resolution or token refresh fails,
    /// or if no client is available for the given DID.
    pub async fn resolve_pds_client_for(
        &self,
        did: &str,
    ) -> Result<Arc<PdsRepoClient>, SkybouncerError> {
        let oc = self.oauth_client.read().clone();
        match self.tenant_registry.get_pds_client(did, oc.as_ref()).await {
            Ok(Some(client)) => Ok(client),
            Ok(None) => {
                let has_enrolled_tenants = self.tenant_registry.count().unwrap_or(0) > 0;
                if self.pds_client.did() == did
                    || self.is_admin(did)
                    || (!has_enrolled_tenants && self.is_protected(did))
                    || (self.is_single_tenant() && self.is_protected(did))
                {
                    Ok(Arc::clone(&self.pds_client))
                } else {
                    Err(SkybouncerError::Config(format!(
                        "No PDS client or OAuth credentials found for tenant {did}"
                    )))
                }
            }
            Err(e) => {
                tracing::error!(
                    did = %did,
                    error = %e,
                    "Failed to resolve PDS client for tenant; refusing to fall back to admin client"
                );
                Err(e)
            }
        }
    }

    /// Retrieves the [`PdsRepoClient`] for a specific protected user, falling back to default engine client.
    ///
    /// Prefer [`Self::resolve_pds_client_for`] to propagate resolution and authentication errors safely.
    pub async fn pds_client_for(&self, did: &str) -> Arc<PdsRepoClient> {
        self.resolve_pds_client_for(did)
            .await
            .unwrap_or_else(|_| Arc::clone(&self.pds_client))
    }

    /// Synchronizes sovereign moderation rules from the protected user's PDS repository.
    ///
    /// Reads `social.skybouncer.config` or list metadata description on the user's PDS.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS communication fails.
    pub async fn sync_sovereign_config(
        &self,
        protected_did: &str,
    ) -> Result<Option<RuleRubric>, SkybouncerError> {
        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        let pds_rubric = crate::modlist::fetch_sovereign_config(&pds_client, protected_did).await?;
        if let Some(ref rubric) = pds_rubric {
            self.gate
                .set_bypass_incoming_followers(protected_did, rubric.bypass_incoming_followers);
            if self.is_enrolled(protected_did) {
                let _ = self.tenant_registry.update_rubric(protected_did, rubric);
            }
            if self.is_admin(protected_did)
                || (self.is_single_tenant() && self.is_protected(protected_did))
            {
                self.set_rubric(rubric.clone());
            }
            info!(
                did = %protected_did,
                rubric = %rubric.prompt,
                "Synchronized sovereign rules from PDS repo"
            );
        }
        Ok(pds_rubric)
    }

    /// Publishes current active rules to the user's sovereign ATProto repository.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS mutation fails.
    pub async fn publish_sovereign_config(
        &self,
        protected_did: &str,
    ) -> Result<String, SkybouncerError> {
        let rubric = self.rubric_for(protected_did);
        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        crate::modlist::publish_sovereign_config(&pds_client, protected_did, &rubric).await
    }

    /// Handles a commit event on `social.skybouncer.config` for a protected user.
    pub(super) fn handle_sovereign_config_commit(
        &self,
        commit: &JetstreamCommit,
    ) -> ProcessCommitResult {
        match commit.operation {
            CommitOperation::Create | CommitOperation::Update => {
                if let Some(ref record_val) = commit.record {
                    match serde_json::from_value::<crate::modlist::SovereignConfigRecord>(
                        record_val.clone(),
                    ) {
                        Ok(config_record) => {
                            let rubric = config_record.to_rubric();
                            self.gate.set_bypass_incoming_followers(
                                &commit.did,
                                rubric.bypass_incoming_followers,
                            );
                            if self.is_enrolled(&commit.did) {
                                let _ = self.tenant_registry.update_rubric(&commit.did, &rubric);
                            }
                            if self.is_admin(&commit.did)
                                || (self.is_single_tenant() && self.is_protected(&commit.did))
                            {
                                self.set_rubric(rubric.clone());
                            }
                            self.stats
                                .sovereign_configs_synced
                                .fetch_add(1, Ordering::Relaxed);
                            info!(
                                did = %commit.did,
                                prompt = %rubric.prompt,
                                sensitivity = %rubric.sensitivity,
                                "Hot-reloaded sovereign moderation rules from Jetstream firehose"
                            );
                            ProcessCommitResult::SovereignConfigSynced(
                                SovereignConfigSyncEvent::Updated {
                                    did: commit.did.clone(),
                                    prompt: rubric.prompt,
                                    sensitivity: rubric.sensitivity,
                                },
                            )
                        }
                        Err(e) => {
                            warn!(
                                did = %commit.did,
                                error = %e,
                                "Failed to parse sovereign config record from firehose commit"
                            );
                            ProcessCommitResult::Ignored
                        }
                    }
                } else {
                    ProcessCommitResult::Ignored
                }
            }
            CommitOperation::Delete => {
                if commit.rkey == crate::modlist::SOVEREIGN_CONFIG_RKEY {
                    let default_rubric = self.config.rubric.clone();
                    self.gate.set_bypass_incoming_followers(
                        &commit.did,
                        default_rubric.bypass_incoming_followers,
                    );
                    if self.is_enrolled(&commit.did) {
                        if let Err(e) = self
                            .tenant_registry
                            .update_rubric(&commit.did, &default_rubric)
                        {
                            warn!(
                                did = %commit.did,
                                error = %e,
                                "Failed to reset tenant rubric in registry on sovereign config deletion"
                            );
                        }
                    }
                    if self.is_admin(&commit.did)
                        || (self.is_single_tenant() && self.is_protected(&commit.did))
                    {
                        self.set_rubric(default_rubric);
                    }
                    self.stats
                        .sovereign_configs_synced
                        .fetch_add(1, Ordering::Relaxed);
                    info!(
                        did = %commit.did,
                        "Sovereign configuration record deleted from PDS via firehose; reset to default rubric"
                    );
                    ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Deleted {
                        did: commit.did.clone(),
                    })
                } else {
                    ProcessCommitResult::Ignored
                }
            }
        }
    }

    /// Handles a commit event on `app.bsky.graph.list` for a protected user.
    pub(super) fn handle_list_commit(&self, commit: &JetstreamCommit) -> ProcessCommitResult {
        if commit.operation != CommitOperation::Create
            && commit.operation != CommitOperation::Update
        {
            return ProcessCommitResult::Ignored;
        }

        if let Some(ref record_val) = commit.record {
            if let Some(desc) = record_val.get("description").and_then(|d| d.as_str()) {
                if let Some(rubric) = crate::modlist::extract_rubric_from_list_description(desc) {
                    self.gate.set_bypass_incoming_followers(
                        &commit.did,
                        rubric.bypass_incoming_followers,
                    );
                    if self.is_enrolled(&commit.did) {
                        let _ = self.tenant_registry.update_rubric(&commit.did, &rubric);
                    }
                    if self.is_admin(&commit.did)
                        || (self.is_single_tenant() && self.is_protected(&commit.did))
                    {
                        self.set_rubric(rubric.clone());
                    }
                    self.stats
                        .sovereign_configs_synced
                        .fetch_add(1, Ordering::Relaxed);
                    info!(
                        did = %commit.did,
                        prompt = %rubric.prompt,
                        sensitivity = %rubric.sensitivity,
                        "Hot-reloaded sovereign moderation rules from list description metadata"
                    );
                    return ProcessCommitResult::SovereignConfigSynced(
                        SovereignConfigSyncEvent::ListMetadataUpdated {
                            did: commit.did.clone(),
                            prompt: rubric.prompt,
                            sensitivity: rubric.sensitivity,
                        },
                    );
                }
            }
        }
        ProcessCommitResult::Ignored
    }
}
