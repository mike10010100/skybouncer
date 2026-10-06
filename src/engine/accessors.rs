use super::*;

impl SkybouncerEngine {
    /// Dynamically adds a protected user DID to the engine's active watch set.
    pub fn add_protected_did(&self, did: impl Into<String>) {
        let mut guard = self.protected_dids.write();
        guard.insert(did.into());
    }

    /// Removes a protected user DID from the engine's active watch set.
    pub fn remove_protected_did(&self, did: &str) -> bool {
        let mut guard = self.protected_dids.write();
        guard.remove(did)
    }

    /// Checks whether a DID is currently protected.
    #[must_use]
    pub fn is_protected(&self, did: &str) -> bool {
        let guard = self.protected_dids.read();
        guard.contains(did)
    }

    /// Returns a snapshot of all currently protected DIDs.
    #[must_use]
    pub fn protected_dids(&self) -> HashSet<String> {
        let guard = self.protected_dids.read();
        guard.clone()
    }

    /// Sub-microsecond check verifying if a protected user follows a candidate.
    #[must_use]
    pub fn is_following(&self, protected_did: &str, candidate_did: &str) -> bool {
        self.follow_graph.is_following(protected_did, candidate_did)
    }

    /// Pre-seeds followed DIDs for a protected user on cold start.
    pub fn hydrate_follows<I, S>(&self, protected_did: impl Into<String>, dids: I) -> usize
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let target = protected_did.into();
        let mut count: usize = 0;
        for (idx, did) in dids.into_iter().enumerate() {
            let rkey = format!("hydrate_{idx}");
            self.follow_graph.add_follow(&target, rkey, did.into());
            count = count.saturating_add(1);
        }
        count
    }

    /// Pre-seeds followed DIDs with real repository rkeys on cold start.
    pub fn hydrate_follow_records<I, K, S>(
        &self,
        protected_did: impl Into<String>,
        records: I,
    ) -> usize
    where
        I: IntoIterator<Item = (K, S)>,
        K: Into<String>,
        S: Into<String>,
    {
        let target = protected_did.into();
        let mut count: usize = 0;
        for (rkey, did) in records {
            self.follow_graph
                .add_follow(&target, rkey.into(), did.into());
            count = count.saturating_add(1);
        }
        count
    }

    /// Pre-seeds incoming follower DIDs for a protected user on cold start.
    ///
    /// The public AppView exposes no repository rkeys for followers, so deterministic
    /// synthetic `hydrate_in_{n}` keys are generated.
    pub fn hydrate_followers<I, S>(&self, protected_did: impl Into<String>, dids: I) -> usize
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.follow_graph.hydrate_followers(protected_did, dids)
    }

    /// Returns `true` if this engine operates in shadow dry-run mode.
    #[must_use]
    pub fn is_dry_run(&self) -> bool {
        self.config.dry_run
    }

    /// Returns `true` if automated moderation actions are temporarily paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Temporarily pauses automated moderation evaluations and PDS list mutations.
    ///
    /// Returns the previous pause state.
    pub fn pause(&self) -> bool {
        self.paused.swap(true, Ordering::SeqCst)
    }

    /// Resumes automated moderation evaluations and PDS list mutations.
    ///
    /// Returns the previous pause state.
    pub fn resume(&self) -> bool {
        self.paused.swap(false, Ordering::SeqCst)
    }

    /// Subscribes to real-time bounce notifications emitted when accounts are bounced on PDS.
    #[must_use]
    pub fn subscribe_bounces(&self) -> broadcast::Receiver<BounceNotification> {
        self.bounce_notifier.subscribe()
    }

    /// Returns a copy of the active configuration with the current live rubric.
    #[must_use]
    pub fn config(&self) -> SkybouncerConfig {
        let mut cfg = self.config.clone();
        cfg.rubric = self.rubric();
        cfg
    }

    /// Returns a copy of the active rule rubric.
    #[must_use]
    pub fn rubric(&self) -> RuleRubric {
        self.rubric.read().clone()
    }

    /// Updates the active moderation rubric in real time across the engine, modlist manager, and classifier.
    pub fn set_rubric(&self, rubric: RuleRubric) {
        *self.rubric.write() = rubric.clone();
        self.modlist_manager.set_rubric(rubric.clone());
        self.classifier.set_rubric(rubric);
    }

    /// Sets whether incoming followers bypass moderation for a protected user.
    ///
    /// Updates only the in-memory gate flag; persistence is handled separately via
    /// [`SkybouncerEngine::add_to_allowlist`]-style registry writes.
    pub fn set_bypass_incoming_followers(&self, protected_did: &str, bypass: bool) {
        self.gate
            .set_bypass_incoming_followers(protected_did, bypass);
    }

    /// Returns whether incoming followers bypass moderation for a protected user.
    #[must_use]
    pub fn bypass_incoming_followers(&self, protected_did: &str) -> bool {
        self.gate.bypass_incoming_followers(protected_did)
    }

    /// Returns a reference to the heuristic classifier.
    #[must_use]
    pub fn heuristic_classifier(&self) -> &HeuristicClassifier {
        &self.heuristic_classifier
    }

    /// Returns a reference to the primary classifier.
    #[must_use]
    pub fn primary_classifier(&self) -> &Arc<dyn Classifier> {
        &self.classifier
    }

    /// Returns a reference to the follow graph.
    #[must_use]
    pub fn follow_graph(&self) -> &Arc<FollowGraph> {
        &self.follow_graph
    }

    /// Returns a reference to the non-followed gate.
    #[must_use]
    pub fn gate(&self) -> &Arc<NonFollowedGate> {
        &self.gate
    }

    /// Returns a reference to the deduplication cache.
    #[must_use]
    pub fn cache(&self) -> &Arc<DeduplicationCache> {
        &self.cache
    }

    /// Returns a reference to the PDS repository client.
    #[must_use]
    pub fn pds_client(&self) -> &Arc<PdsRepoClient> {
        &self.pds_client
    }

    /// Returns a reference to the operational statistics.
    #[must_use]
    pub fn stats(&self) -> &Arc<EngineStats> {
        &self.stats
    }

    /// Persists the current cumulative telemetry counters to durable storage.
    ///
    /// Called periodically and during graceful shutdown so dashboard KPI totals survive
    /// process restarts and deployments.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the snapshot cannot be serialized or written.
    pub fn persist_stats(&self) -> Result<(), SkybouncerError> {
        let snapshot = self.stats.snapshot();
        self.cache.save_dashboard_stats(&snapshot)
    }

    /// Returns a reference to the evaluation rate limiter.
    #[must_use]
    pub fn rate_limiter(&self) -> &Arc<EvaluationRateLimiter> {
        &self.rate_limiter
    }

    /// Returns a reference to the context enricher.
    #[must_use]
    pub fn enricher(&self) -> &Arc<dyn ContextEnricher> {
        &self.enricher
    }

    /// Returns a reference to the multi-tenant registry.
    #[must_use]
    pub fn tenant_registry(&self) -> &Arc<TenantRegistry> {
        &self.tenant_registry
    }
}
