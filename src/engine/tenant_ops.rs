use super::*;

impl SkybouncerEngine {
    /// Enrolls or updates an active tenant in the registry and active watch set.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if tenant registration fails.
    pub fn enroll_tenant(&self, tenant: Tenant) -> Result<(), SkybouncerError> {
        let did = tenant.did.clone();
        let is_active = tenant.is_active;
        let bypass_followers = tenant.rubric.as_ref().map(|r| r.bypass_incoming_followers);
        self.tenant_registry.register_or_update(&tenant)?;
        if let Some(bypass) = bypass_followers {
            self.gate.set_bypass_incoming_followers(&did, bypass);
        }
        if is_active {
            self.add_protected_did(did);
        } else {
            self.remove_protected_did(&did);
        }
        Ok(())
    }

    /// Atomically enrolls or updates an OAuth-authenticated tenant from `/oauth/callback`
    /// without overwriting concurrent rubric or pause edits, and syncs runtime `protected_dids`
    /// and `gate` state from the persisted DB row.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if session validation, encryption, or persistence fails.
    pub fn enroll_oauth_tenant(
        &self,
        did: &str,
        handle: Option<&str>,
        session: &skyauth::session::OAuthSession,
    ) -> Result<(), SkybouncerError> {
        let (is_active, rubric) = self
            .tenant_registry
            .upsert_oauth_session(did, handle, session)?;
        if let Some(ref r) = rubric {
            self.gate
                .set_bypass_incoming_followers(did, r.bypass_incoming_followers);
        }
        if is_active {
            self.add_protected_did(did.to_string());
        } else {
            self.remove_protected_did(did);
        }
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

    /// Returns `true` only when at most one protected DID and at most one enrolled tenant exist,
    /// they refer to the same DID (if both exist), and any configured `admin_did` matches that sole DID.
    ///
    /// Fails closed (`false`) if the tenant registry cannot be queried.
    #[must_use]
    pub fn is_single_tenant(&self) -> bool {
        let protected: Vec<String> = self.protected_dids.read().iter().cloned().collect();
        if protected.len() > 1 {
            return false;
        }
        let Ok(tenants) = self.tenant_registry.list_all() else {
            return false;
        };
        if tenants.len() > 1 {
            return false;
        }

        let sole_protected = protected.first().map(String::as_str);
        let sole_tenant = tenants.first().map(|t| t.did.as_str());
        if let (Some(p), Some(t)) = (sole_protected, sole_tenant) {
            if p != t {
                return false;
            }
        }
        if let Some(admin) = self
            .config
            .admin_did
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            if let Some(p) = sole_protected {
                if !admin.eq_ignore_ascii_case(p) {
                    return false;
                }
            }
            if let Some(t) = sole_tenant {
                if !admin.eq_ignore_ascii_case(t) {
                    return false;
                }
            }
        }
        true
    }

    /// Checks whether a tenant is paused (or the entire engine is paused),
    /// including when the tenant's OAuth session requires manual re-authentication.
    #[must_use]
    pub fn is_tenant_paused(&self, did: &str) -> bool {
        if self.is_paused() {
            return true;
        }
        match self.tenant_registry.get(did) {
            Ok(Some(tenant)) => {
                !tenant.is_active || self.tenant_registry.is_reauth_required(did).unwrap_or(true)
            }
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
        let was_reauth_required = self
            .tenant_registry
            .is_reauth_required(did)
            .unwrap_or(false);
        let oc = self.oauth_client.read().clone();
        match self.tenant_registry.get_pds_client(did, oc.as_ref()).await {
            Ok(Some(client)) => Ok(client),
            Ok(None) => {
                let allow_fallback = self.pds_client.did() == did
                    || (self.is_admin(did)
                        && (self.pds_client.did() == did || self.config.dry_run))
                    || (self.config.dry_run && self.is_single_tenant() && self.is_protected(did));
                if allow_fallback {
                    Ok(Arc::clone(&self.pds_client))
                } else {
                    Err(SkybouncerError::Config(format!(
                        "No PDS client or OAuth credentials found for tenant {did}"
                    )))
                }
            }
            Err(e) => {
                self.notify_reauth_if_pending(did, was_reauth_required);
                tracing::error!(
                    did = %did,
                    error = %e,
                    "Failed to resolve PDS client for tenant; refusing to fall back to admin client"
                );
                Err(e)
            }
        }
    }

    fn notify_reauth_if_pending(&self, did: &str, was_reauth_required: bool) {
        if !was_reauth_required
            && self
                .tenant_registry
                .is_reauth_notification_pending(did)
                .unwrap_or(false)
        {
            let handle = self
                .tenant_registry
                .get(did)
                .ok()
                .flatten()
                .and_then(|t| t.handle);
            let _ = self.reauth_notifier.send(ReauthNotification {
                target_did: did.to_string(),
                handle,
            });
        }
    }

    pub(crate) fn is_pds_auth_401_or_expired(err: &SkybouncerError) -> bool {
        match err {
            SkybouncerError::Auth(msg) => {
                let lower = msg.to_ascii_lowercase();
                lower.contains("expired") || lower.contains("invalidtoken")
            }
            SkybouncerError::Repo(msg) => {
                msg.contains("status 401")
                    || msg.contains("401 Unauthorized")
                    || msg.contains("ExpiredToken")
                    || msg.contains("InvalidToken")
            }
            _ => false,
        }
    }

    /// Executes an async PDS operation for `did`, performing a single-flight OAuth token refresh
    /// and one retry if the PDS rejects the access token with HTTP 401 (`ExpiredToken`/`InvalidToken`).
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if client resolution, token refresh, or the PDS operation fails.
    pub async fn with_pds_client_401_retry<T, F, Fut>(
        &self,
        did: &str,
        op: F,
    ) -> Result<T, SkybouncerError>
    where
        F: Fn(Arc<PdsRepoClient>) -> Fut,
        Fut: std::future::Future<Output = Result<T, SkybouncerError>>,
    {
        let client = self.resolve_pds_client_for(did).await?;
        match op(Arc::clone(&client)).await {
            Ok(val) => Ok(val),
            Err(err) if Self::is_pds_auth_401_or_expired(&err) => {
                let was_reauth_required = self
                    .tenant_registry
                    .is_reauth_required(did)
                    .unwrap_or(false);
                let oc = self.oauth_client.read().clone();
                match self
                    .tenant_registry
                    .force_refresh_pds_client(did, &client, oc.as_ref())
                    .await
                {
                    Ok(Some(refreshed)) => op(refreshed).await,
                    Ok(None) => Err(err),
                    Err(refresh_err) => {
                        self.notify_reauth_if_pending(did, was_reauth_required);
                        Err(refresh_err)
                    }
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Proactively refreshes OAuth sessions for active enrolled tenants whose access tokens
    /// are expired or expiring within 60 seconds, keeping sliding refresh token grants alive
    /// even during quiet periods without incoming firehose bounces.
    ///
    /// Skips tenants already flagged as requiring manual re-authentication (`reauth_required = 1`).
    /// Returns the number of tenant sessions refreshed.
    pub async fn refresh_expiring_tenant_sessions(&self) -> usize {
        if self.oauth_client.read().is_none() {
            return 0;
        }
        let tenants = match self.tenant_registry.list_active() {
            Ok(list) => list,
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to list active tenants for background session refresh"
                );
                return 0;
            }
        };

        let mut refreshed = 0;
        for tenant in tenants {
            if self
                .tenant_registry
                .is_reauth_required(&tenant.did)
                .unwrap_or(false)
            {
                continue;
            }
            let Some(ref session) = tenant.session else {
                continue;
            };
            if session.is_expired_with_leeway(Duration::from_secs(60)) {
                match self.resolve_pds_client_for(&tenant.did).await {
                    Ok(_) => {
                        refreshed += 1;
                    }
                    Err(e) => {
                        warn!(
                            did = %tenant.did,
                            error = %e,
                            "Proactive background OAuth session refresh failed for tenant"
                        );
                    }
                }
            }
        }
        refreshed
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
        let fetched = self
            .with_pds_client_401_retry(protected_did, |pds_client| async move {
                crate::modlist::fetch_sovereign_config_with_cid(&pds_client, protected_did).await
            })
            .await?;

        let mut pds_rubric = None;
        if let Some((mut rubric, cid)) = fetched {
            let upgraded_legacy = rubric.upgrade_legacy_prompt();
            self.gate
                .set_bypass_incoming_followers(protected_did, rubric.bypass_incoming_followers);
            if self.is_enrolled(protected_did) {
                let _ = self.tenant_registry.update_rubric(protected_did, &rubric);
            }
            if self.is_admin(protected_did)
                || (self.is_single_tenant() && self.is_protected(protected_did))
            {
                self.set_rubric(rubric.clone());
            }
            if upgraded_legacy {
                let _publish_guard = self
                    .sovereign_publish_locks
                    .shard_for(protected_did)
                    .lock()
                    .await;
                let mod_list_uri = self
                    .cache
                    .get_mod_list(protected_did)
                    .ok()
                    .flatten()
                    .map(|c| c.list_uri);
                let writeback_res = self
                    .with_pds_client_401_retry(protected_did, |pds_client| {
                        let rubric_ref = &rubric;
                        let list_uri_ref = mod_list_uri.as_deref();
                        let cid_ref = cid.as_deref();
                        async move {
                            crate::modlist::publish_sovereign_config_with_options(
                                &pds_client,
                                protected_did,
                                rubric_ref,
                                list_uri_ref,
                                cid_ref,
                            )
                            .await
                        }
                    })
                    .await;
                match writeback_res {
                    Ok(uri) => {
                        info!(
                            did = %protected_did,
                            %uri,
                            "Upgraded unmodified legacy sovereign rubric to target-scoped wording on PDS"
                        );
                    }
                    Err(e) => {
                        warn!(
                            did = %protected_did,
                            error = %e,
                            "Upgraded legacy sovereign rubric in memory/DB, but PDS writeback failed"
                        );
                    }
                }
            }
            info!(
                did = %protected_did,
                rubric = %rubric.prompt,
                "Synchronized sovereign rules from PDS repo"
            );
            pds_rubric = Some(rubric);
        }
        Ok(pds_rubric)
    }

    /// Publishes current active rules to the user's sovereign ATProto repository,
    /// serialized per tenant and protected by `swapRecord` CAS.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS mutation fails.
    pub async fn publish_sovereign_config(
        &self,
        protected_did: &str,
    ) -> Result<String, SkybouncerError> {
        let _publish_guard = self
            .sovereign_publish_locks
            .shard_for(protected_did)
            .lock()
            .await;
        let rubric = self.rubric_for(protected_did);
        let mod_list_uri = self
            .cache
            .get_mod_list(protected_did)
            .ok()
            .flatten()
            .map(|c| c.list_uri);
        self.with_pds_client_401_retry(protected_did, |pds_client| {
            let rubric_ref = &rubric;
            let list_uri_ref = mod_list_uri.as_deref();
            async move {
                crate::modlist::publish_sovereign_config_with_options(
                    &pds_client,
                    protected_did,
                    rubric_ref,
                    list_uri_ref,
                    None,
                )
                .await
            }
        })
        .await
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
