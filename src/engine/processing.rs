use super::*;

impl SkybouncerEngine {
    /// Creates a builder to configure and instantiate a [`SkybouncerEngine`].
    #[must_use]
    pub fn builder(config: SkybouncerConfig) -> SkybouncerEngineBuilder {
        SkybouncerEngineBuilder::new(config)
    }

    /// Creates a new [`SkybouncerEngine`] with direct component references.
    #[must_use]
    pub fn new(
        config: SkybouncerConfig,
        follow_graph: Arc<FollowGraph>,
        gate: Arc<NonFollowedGate>,
        classifier: Arc<dyn Classifier>,
        modlist_manager: Arc<ModListManager>,
        pds_client: Arc<PdsRepoClient>,
    ) -> Self {
        let cache = Arc::clone(modlist_manager.cache());
        let tenant_registry = Arc::new(
            TenantRegistry::from_connection(cache.connection())
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "Failed to initialize TenantRegistry from cache connection; falling back to in-memory registry");
                    TenantRegistry::open_in_memory().unwrap_or_else(|e2| {
                        tracing::error!(error = %e2, "Failed to initialize in-memory TenantRegistry; using emergency fallback");
                        TenantRegistry::fallback()
                    })
                }),
        );
        let heuristic_classifier = if config.enable_heuristic_prefilter {
            HeuristicClassifier::default()
        } else {
            HeuristicClassifier::empty()
        };
        let modlist_manager = if config.dry_run && !modlist_manager.is_dry_run() {
            Arc::new((*modlist_manager).clone().with_dry_run(true))
        } else {
            modlist_manager
        };
        let mut protected = config.protected_dids.clone();
        if let Ok(active) = tenant_registry.list_active() {
            for t in active {
                protected.insert(t.did);
            }
        }
        let protected_dids = Arc::new(RwLock::new(protected));
        let rubric = Arc::new(RwLock::new(config.rubric.clone()));
        let rate_limiter = Arc::new(EvaluationRateLimiter::new(
            config.rate_limiter_config.clone(),
        ));
        let enricher: Arc<dyn ContextEnricher> = Arc::new(NoopContextEnricher);
        let stats = Arc::new(load_persisted_stats(&cache));
        let paused = Arc::new(AtomicBool::new(false));
        let (bounce_notifier, _) = broadcast::channel(256);
        let oauth_client = Arc::new(RwLock::new(None));
        let handle_cache = Arc::new(RwLock::new(HashMap::new()));

        if let Ok(loaded_allowlists) = cache.load_all_allowlists() {
            let mut guard = gate.allowlist().write();
            for (prot, authors) in loaded_allowlists {
                guard.entry(prot).or_default().extend(authors);
            }
        }

        for did in &config.protected_dids {
            gate.set_bypass_incoming_followers(did, config.rubric.bypass_incoming_followers);
        }

        Self {
            config,
            protected_dids,
            rubric,
            follow_graph,
            gate,
            heuristic_classifier,
            classifier,
            modlist_manager,
            cache,
            tenant_registry,
            pds_client,
            rate_limiter,
            enricher,
            stats,
            paused,
            bounce_notifier,
            oauth_client,
            handle_cache,
        }
    }

    /// Configures the active [`AtprotoOAuthClient`] for automatic background session refreshes.
    pub fn set_oauth_client(&self, client: Arc<AtprotoOAuthClient>) {
        *self.oauth_client.write() = Some(Arc::clone(&client));
        self.tenant_registry.set_oauth_client(client);
    }

    /// Returns a reference to the active [`AtprotoOAuthClient`], if configured.
    #[must_use]
    pub fn oauth_client(&self) -> Option<Arc<AtprotoOAuthClient>> {
        self.oauth_client.read().clone()
    }

    /// Evaluates a single Jetstream commit through the full moderation pipeline.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if classifier evaluation, cache query, or PDS mutation fails.
    #[instrument(skip(self, commit), fields(collection = %commit.collection, did = %commit.did, rkey = %commit.rkey))]
    pub async fn process_commit(
        &self,
        commit: &JetstreamCommit,
    ) -> Result<ProcessCommitResult, SkybouncerError> {
        match self.dispatch_commit(commit) {
            CommitDispatch::Resolved(result) => Ok(result),
            CommitDispatch::Interactions(interactions) => {
                let mut outcomes = Vec::with_capacity(interactions.len());
                for interaction in interactions {
                    outcomes.push(self.process_interaction(interaction).await?);
                }
                Ok(ProcessCommitResult::InteractionsProcessed(outcomes))
            }
        }
    }

    /// Evaluates a single Jetstream commit, dispatching candidate interactions to a decoupled evaluation queue.
    ///
    /// Fast-path operations (follow graph sync, non-post filtering, self/followed gate checks,
    /// dedup cache hits, and evaluation cache hits) are completed immediately (<1µs to <50µs).
    /// Candidates requiring model evaluation are enqueued to `eval_tx` without blocking the caller.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if cache query or PDS mutation fails.
    #[instrument(skip(self, commit, eval_tx), fields(collection = %commit.collection, did = %commit.did, rkey = %commit.rkey))]
    pub async fn process_commit_queued(
        &self,
        commit: &JetstreamCommit,
        eval_tx: &mpsc::Sender<Interaction>,
    ) -> Result<ProcessCommitResult, SkybouncerError> {
        match self.dispatch_commit(commit) {
            CommitDispatch::Resolved(result) => Ok(result),
            CommitDispatch::Interactions(interactions) => {
                let mut outcomes = Vec::with_capacity(interactions.len());
                for interaction in interactions {
                    outcomes.push(
                        self.process_interaction_queued(interaction, eval_tx)
                            .await?,
                    );
                }
                Ok(ProcessCommitResult::InteractionsProcessed(outcomes))
            }
        }
    }

    /// Runs the commit-level tiers shared by [`Self::process_commit`] and
    /// [`Self::process_commit_queued`]: follow/config/list intercepts, post filtering,
    /// and target matching.
    ///
    /// Returns either a fully resolved [`ProcessCommitResult`] or the extracted
    /// candidate interactions awaiting per-interaction evaluation.
    pub(super) fn dispatch_commit(&self, commit: &JetstreamCommit) -> CommitDispatch {
        self.stats.commits_received.fetch_add(1, Ordering::Relaxed);

        // Tier 0: Follow Collection Intercept
        if commit.collection.as_str() == "app.bsky.graph.follow" {
            let sync_event = {
                let guard = self.protected_dids.read();
                self.follow_graph.handle_commit(commit, &guard)
            };
            if sync_event != FollowSyncEvent::Ignored {
                self.stats
                    .follow_sync_events
                    .fetch_add(1, Ordering::Relaxed);
                self.stats.follows_synced.fetch_add(1, Ordering::Relaxed);
                debug!(event = ?sync_event, "Synchronized follow graph from firehose commit");
            }
            return CommitDispatch::Resolved(ProcessCommitResult::FollowSynced(sync_event));
        }

        // Tier 0.5: Sovereign Config Collection Intercept (PRD §2.2)
        if commit.collection.as_str() == crate::modlist::SOVEREIGN_CONFIG_COLLECTION {
            if self.is_protected(&commit.did) {
                return CommitDispatch::Resolved(self.handle_sovereign_config_commit(commit));
            }
            return CommitDispatch::Resolved(ProcessCommitResult::Ignored);
        }

        // Tier 0.6: List Metadata Intercept (PRD §2.2)
        if commit.collection.as_str() == "app.bsky.graph.list" {
            if self.is_protected(&commit.did) {
                return CommitDispatch::Resolved(self.handle_list_commit(commit));
            }
            return CommitDispatch::Resolved(ProcessCommitResult::Ignored);
        }

        // Tier 1: Post Collection & Operation Filter
        if commit.collection.as_str() != "app.bsky.feed.post"
            || commit.operation != CommitOperation::Create
        {
            return CommitDispatch::Resolved(ProcessCommitResult::Ignored);
        }

        // Tier 2: Target Matcher Extraction
        let interactions = {
            let guard = self.protected_dids.read();
            TargetMatcher::match_all_interactions(commit, &guard)
        };
        if interactions.is_empty() {
            return CommitDispatch::Resolved(ProcessCommitResult::NoMatch);
        }

        let count = u64::try_from(interactions.len()).unwrap_or(0);
        self.stats
            .interactions_matched
            .fetch_add(count, Ordering::Relaxed);

        CommitDispatch::Interactions(interactions)
    }

    /// Evaluates an extracted interaction through the fast-path gates and caches,
    /// enqueueing surviving candidates to the decoupled background evaluation queue.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if cache query or PDS mutation fails.
    #[instrument(skip(self, interaction, eval_tx), fields(author = %interaction.author_did, target = %interaction.target_did, post_uri = %interaction.post_uri))]
    pub async fn process_interaction_queued(
        &self,
        interaction: Interaction,
        eval_tx: &mpsc::Sender<Interaction>,
    ) -> Result<InteractionOutcome, SkybouncerError> {
        let author_did = interaction.author_did.clone();
        let target_did = interaction.target_did.clone();
        let post_uri = interaction.post_uri.clone();

        match self.fast_path(&interaction).await? {
            FastPath::Resolved(outcome) => return Ok(outcome),
            FastPath::Heuristic(outcome, _) => return outcome,
            FastPath::Continue => {}
        }

        // Enqueue candidate for background evaluation
        match eval_tx.try_send(interaction) {
            Ok(()) => {
                self.stats
                    .eval_queue_enqueued
                    .fetch_add(1, Ordering::Relaxed);
                debug!(
                    author = %author_did,
                    target = %target_did,
                    "Candidate enqueued for background evaluation"
                );
                Ok(InteractionOutcome::QueuedForEvaluation {
                    author_did,
                    target_did,
                    post_uri,
                })
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats
                    .eval_queue_overflows
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    author = %author_did,
                    target = %target_did,
                    "Evaluation queue saturated; shedding load to preserve Jetstream subscriber throughput"
                );
                Ok(InteractionOutcome::QueueOverflow {
                    author_did,
                    target_did,
                    post_uri,
                })
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("Evaluation queue channel closed");
                Err(SkybouncerError::Ingestion(
                    "Evaluation queue channel closed".to_string(),
                ))
            }
        }
    }

    /// Evaluates an extracted interaction through the non-followed gate, caches, classifiers, and modlist mutator synchronously.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if classifier evaluation, cache query, or PDS mutation fails.
    #[instrument(skip(self, interaction), fields(author = %interaction.author_did, target = %interaction.target_did, post_uri = %interaction.post_uri))]
    pub async fn process_interaction(
        &self,
        interaction: Interaction,
    ) -> Result<InteractionOutcome, SkybouncerError> {
        let target_did = interaction.target_did.clone();

        match self.fast_path(&interaction).await? {
            FastPath::Resolved(outcome) => return Ok(outcome),
            FastPath::Heuristic(outcome, verdict) => {
                let outcome_str = match &outcome {
                    Ok(InteractionOutcome::Bounced { .. }) => "Bounced (Regex Pre-filter)",
                    Ok(InteractionOutcome::BelowThreshold { .. }) => {
                        "Below Threshold (Regex Pre-filter)"
                    }
                    Ok(other) => other.label(),
                    Err(_) => "Error (Regex Pre-filter)",
                };
                let target_handle = self.target_handle(&target_did);
                let log_entry = crate::modlist::cache::NewEvaluationLog::heuristic(
                    &interaction,
                    &interaction.post_uri,
                    &verdict,
                    crate::modlist::EvaluationLogContext {
                        source: "live",
                        outcome: outcome_str,
                    },
                    String::new(),
                    target_handle,
                );
                if let Err(e) = self.cache.record_evaluation_log(&log_entry) {
                    tracing::warn!(error = %e, "Failed to record evaluation log in cache");
                    self.stats
                        .errors_encountered
                        .fetch_add(1, Ordering::Relaxed);
                }
                return outcome;
            }
            FastPath::Continue => {}
        }

        self.evaluate_candidate(interaction).await
    }

    /// Runs the per-interaction fast-path tiers shared by the sync and queued processors:
    /// the cost-control gate (Tier 3), pause check (Tier 3.5), dedup cache (Tier 4),
    /// evaluation TTL cache (Tier 5), and regex heuristic pre-filter (Tier 6).
    ///
    /// Returns a terminal outcome when the interaction is resolved without a model call,
    /// [`FastPath::Heuristic`] when a heuristic violation was acted upon (so the sync
    /// caller can emit its audit log), or [`FastPath::Continue`] when the caller must
    /// proceed to model evaluation (sync) or enqueueing (queued).
    async fn fast_path(&self, interaction: &Interaction) -> Result<FastPath, SkybouncerError> {
        let author_did = interaction.author_did.clone();
        let target_did = interaction.target_did.clone();
        let post_uri = interaction.post_uri.clone();

        // Tier 3: Non-Followed Cost Control Gate (<1µs, $0 cost)
        let decision = self.gate.evaluate(interaction.clone());
        if let GateDecision::Bypassed { reason, .. } = decision {
            match reason {
                BypassReason::SelfInteraction => {
                    self.stats
                        .gate_bypassed_self
                        .fetch_add(1, Ordering::Relaxed);
                }
                BypassReason::FollowedAuthor => {
                    self.stats
                        .gate_bypassed_followed
                        .fetch_add(1, Ordering::Relaxed);
                }
                BypassReason::FollowerAuthor => {
                    self.stats
                        .gate_bypassed_follower
                        .fetch_add(1, Ordering::Relaxed);
                }
                BypassReason::AllowlistedAuthor => {
                    self.stats
                        .gate_bypassed_allowlist
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            debug!(reason = ?reason, "Bypassed interaction at gate with zero cost");
            return Ok(FastPath::Resolved(InteractionOutcome::Bypassed {
                reason,
                author_did,
                target_did,
            }));
        }

        // Tier 3.5: Moderation Pause Check
        if self.is_tenant_paused(&target_did) {
            debug!(
                author = %author_did,
                target = %target_did,
                "Engine or tenant is paused; bypassing interaction evaluation"
            );
            return Ok(FastPath::Resolved(InteractionOutcome::Paused {
                author_did,
                target_did,
            }));
        }

        // Tier 4: Deduplication Cache Check (<50µs, $0 cost)
        self.stats
            .candidates_evaluated
            .fetch_add(1, Ordering::Relaxed);
        if self.cache.is_bounced_for(&target_did, &author_did)? {
            self.stats.dedup_cache_hits.fetch_add(1, Ordering::Relaxed);
            debug!("Author already bounced in deduplication cache; skipping evaluation");
            return Ok(FastPath::Resolved(InteractionOutcome::AlreadyBounced {
                author_did,
                target_did,
            }));
        }

        // Tier 5: Evaluation TTL Cache Check (<50µs, $0 cost)
        let eval_cache_key = format!("{}:{}", post_uri, target_did);
        let cached_verdict = self.cache.get_evaluation(&eval_cache_key)?;
        if let Some(verdict) = cached_verdict {
            self.stats.eval_cache_hits.fetch_add(1, Ordering::Relaxed);
            debug!("Evaluation cache hit for post; reusing verdict");
            return Ok(FastPath::Resolved(
                self.act_on_verdict(interaction, verdict).await?,
            ));
        }

        // Tier 6: Zero-Cost Regex Heuristic Pre-Filter (<500ns, $0 cost)
        let heuristic_verdict = self.heuristic_classifier.evaluate(interaction);
        if heuristic_verdict.is_violation() {
            self.stats
                .heuristic_violations
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .violations_detected
                .fetch_add(1, Ordering::Relaxed);
            debug!("Heuristic regex pre-filter detected violation at zero cost");

            let _ = self.cache.set_evaluation(
                &eval_cache_key,
                &author_did,
                &heuristic_verdict,
                self.config.evaluation_ttl,
            );

            let outcome = self
                .act_on_verdict(interaction, heuristic_verdict.clone())
                .await;
            return Ok(FastPath::Heuristic(outcome, heuristic_verdict));
        }

        Ok(FastPath::Continue)
    }

    /// Evaluates a candidate interaction against the primary classifier model and performs PDS bounce if violated.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if classifier evaluation, cache query, or PDS mutation fails.
    #[instrument(skip(self, interaction), fields(author = %interaction.author_did, target = %interaction.target_did, post_uri = %interaction.post_uri))]
    pub async fn evaluate_candidate(
        &self,
        interaction: Interaction,
    ) -> Result<InteractionOutcome, SkybouncerError> {
        let author_did = interaction.author_did.clone();
        let target_did = interaction.target_did.clone();
        let post_uri = interaction.post_uri.clone();

        if self.is_tenant_paused(&target_did) {
            debug!(
                author = %author_did,
                target = %target_did,
                "Engine or tenant is paused; bypassing queued evaluation"
            );
            return Ok(InteractionOutcome::Paused {
                author_did,
                target_did,
            });
        }

        // Double check dedup cache before making expensive model call,
        // in case a prior candidate from the same author already resulted in a bounce while this was queued!
        if self.cache.is_bounced_for(&target_did, &author_did)? {
            self.stats.dedup_cache_hits.fetch_add(1, Ordering::Relaxed);
            debug!(
                author = %author_did,
                target = %target_did,
                "Author bounced while candidate was queued; skipping model call"
            );
            return Ok(InteractionOutcome::AlreadyBounced {
                author_did,
                target_did,
            });
        }

        // Tier 4: Per-User Evaluation Rate Limiter (Anti-Denial-of-Wallet, PRD §5.2) - checked at dequeue
        if !self.rate_limiter.check_and_record(&target_did) {
            self.stats
                .rate_limited_evaluations
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                target = %target_did,
                author = %author_did,
                "Evaluation rate limit reached for target user; skipping external model call"
            );
            return Ok(InteractionOutcome::RateLimited {
                author_did,
                target_did,
                reason: "Tier-4 Anti-Denial-of-Wallet rate limit exceeded".to_string(),
            });
        }

        // Context Enricher: Fetch author profile & parent post context (PRD §3 & §4.2)
        let enriched = self.enricher.enrich(&interaction).await;
        let interaction = if !enriched.is_empty() {
            self.stats
                .context_enrichments
                .fetch_add(1, Ordering::Relaxed);
            interaction.with_enriched_context(enriched)
        } else {
            interaction
        };

        // Tier 7: Primary Model Evaluation
        self.stats.model_evaluations.fetch_add(1, Ordering::Relaxed);
        self.stats.tier1_evaluations.fetch_add(1, Ordering::Relaxed);
        let target_rubric = self.rubric_for(&target_did);
        let interaction = interaction.with_rubric(target_rubric.clone());
        let detailed_eval = self
            .classifier
            .classify_detailed_with_stats_and_rubric(&interaction, Some(&target_rubric), true)
            .await
            .inspect_err(|_e| {
                self.stats
                    .errors_encountered
                    .fetch_add(1, Ordering::Relaxed);
            })?;

        if detailed_eval.escalated {
            self.stats.tier2_evaluations.fetch_add(1, Ordering::Relaxed);
            if detailed_eval
                .escalation_reason
                .as_deref()
                .unwrap_or("")
                .contains("image")
            {
                self.stats
                    .tier2_image_escalations
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                self.stats
                    .tier2_uncertainty_escalations
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        let model_verdict = detailed_eval.final_verdict.clone();
        if model_verdict.is_violation() {
            self.stats
                .violations_detected
                .fetch_add(1, Ordering::Relaxed);
        }

        // Cache the verdict with configured TTL
        let eval_cache_key = format!("{}:{}", post_uri, target_did);
        let _ = self.cache.set_evaluation(
            &eval_cache_key,
            &author_did,
            &model_verdict,
            self.config.evaluation_ttl,
        );

        // Tier 8: Rubric Sensitivity Gate & Sovereign PDS Bounce
        let outcome = self
            .act_on_verdict(&interaction, model_verdict.clone())
            .await;

        let outcome_str = match &outcome {
            Ok(outcome) => outcome.label(),
            Err(_) => "Error",
        };

        let author_handle = interaction
            .enriched_context
            .as_ref()
            .and_then(|c| c.author.as_ref())
            .and_then(|a| a.handle.clone())
            .unwrap_or_default();

        let target_handle = self.target_handle(&target_did);

        let log_entry = crate::modlist::cache::NewEvaluationLog::from_tiered(
            &interaction,
            &interaction.post_uri,
            &detailed_eval,
            &model_verdict,
            crate::modlist::EvaluationLogContext {
                source: "live",
                outcome: outcome_str,
            },
            author_handle,
            target_handle,
        );

        if let Err(e) = self.cache.record_evaluation_log(&log_entry) {
            tracing::warn!(error = %e, "Failed to record evaluation log in cache");
            self.stats
                .errors_encountered
                .fetch_add(1, Ordering::Relaxed);
        }

        outcome
    }

    /// Evaluates a classifier verdict against the rubric sensitivity threshold and executes PDS bounce if actionable.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS mutation or cache recording fails.
    #[instrument(skip(self, interaction, verdict), fields(author = %interaction.author_did, target = %interaction.target_did, post_uri = %interaction.post_uri))]
    pub async fn act_on_verdict(
        &self,
        interaction: &Interaction,
        verdict: Verdict,
    ) -> Result<InteractionOutcome, SkybouncerError> {
        let author_did = interaction.author_did.clone();
        let target_did = interaction.target_did.clone();
        let post_uri = interaction.post_uri.clone();
        let post_text = interaction.text.clone();

        match verdict {
            Verdict::Permitted { reason, .. } => {
                self.stats.permitted.fetch_add(1, Ordering::Relaxed);
                Ok(InteractionOutcome::Permitted {
                    author_did,
                    target_did,
                    reason,
                })
            }
            Verdict::Violation {
                category,
                confidence,
                reason,
            } => {
                let rubric = self.rubric_for(&target_did);
                let threshold = rubric.sensitivity.threshold();
                if !rubric.meets_threshold(&category, confidence) {
                    self.stats
                        .bounces_skipped_rubric
                        .fetch_add(1, Ordering::Relaxed);
                    self.stats.permitted.fetch_add(1, Ordering::Relaxed);
                    debug!(
                        confidence = %confidence,
                        threshold = %threshold,
                        "Violation confidence below rubric threshold; skipping bounce"
                    );
                    return Ok(InteractionOutcome::BelowThreshold {
                        author_did,
                        target_did,
                        category,
                        confidence,
                        threshold,
                    });
                }

                // Actionable violation: bounce on sovereign PDS
                let expires_at = rubric.bounce_duration.expires_at_us(current_time_us());
                let pds_client = self.resolve_pds_client_for(&target_did).await?;
                let bounce_result = self
                    .modlist_manager
                    .bounce(
                        &pds_client,
                        BounceRequest::new(
                            &target_did,
                            &author_did,
                            &category,
                            confidence,
                            &reason,
                            &post_uri,
                        )
                        .with_post_text(&post_text)
                        .with_expires_at(expires_at),
                    )
                    .await
                    .inspect_err(|_e| {
                        self.stats
                            .errors_encountered
                            .fetch_add(1, Ordering::Relaxed);
                    })?;

                match bounce_result {
                    Some(listitem_uri) => {
                        self.stats.bounces_executed.fetch_add(1, Ordering::Relaxed);
                        self.stats.bounced.fetch_add(1, Ordering::Relaxed);
                        info!(
                            violator = %author_did,
                            listitem = %listitem_uri,
                            category = %category,
                            confidence = %confidence,
                            "Bounced violator on sovereign PDS"
                        );

                        // Emit proactive bounce notification for alert dispatchers
                        let _ = self.bounce_notifier.send(BounceNotification {
                            target_did: target_did.clone(),
                            violator_did: author_did.clone(),
                            category: category.clone(),
                            confidence,
                            reason: reason.clone(),
                            post_uri: post_uri.clone(),
                            post_snippet: interaction.text.chars().take(200).collect(),
                        });

                        Ok(InteractionOutcome::Bounced {
                            author_did,
                            target_did,
                            listitem_uri,
                            category,
                            confidence,
                            reason,
                        })
                    }
                    None => {
                        // Double-checked locking detected concurrent task already bounced author
                        self.stats.dedup_cache_hits.fetch_add(1, Ordering::Relaxed);
                        Ok(InteractionOutcome::AlreadyBounced {
                            author_did,
                            target_did,
                        })
                    }
                }
            }
        }
    }
}
