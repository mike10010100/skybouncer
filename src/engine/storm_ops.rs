use super::*;

use crate::dogpile::{
    apply_postgate_detach, apply_threadgate, compute_composite_score, compute_direct_ratio,
    compute_dunk_ratio, compute_power_asymmetry, compute_structural_score, parse_owned_post_uri,
    remove_threadgate, severity_from_score, CatalystInfo, PostEngagementSnapshot, StormEvent,
    StormNotification, StormStanceInput, StormStanceVerdict, StormStatus, SurgeCandidate,
    ThreadgatePolicy,
};

impl SkybouncerEngine {
    /// Evaluates a Stage 1 [`SurgeCandidate`] through Stage 2 AppView engagement/catalyst
    /// enrichment, Stage 3 bundled LLM stance verification, and Storm Mode activation.
    ///
    /// Returns `Ok(Some(StormEvent))` when a dogpile storm is confirmed and persisted,
    /// or `Ok(None)` when the surge is suppressed (e.g. benign viral post or paused tenant).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if storm persistence fails.
    #[instrument(skip(self, candidate), fields(target = %candidate.target_did, focal = %candidate.focal_post_uri))]
    pub async fn evaluate_storm_candidate(
        &self,
        candidate: SurgeCandidate,
    ) -> Result<Option<StormEvent>, SkybouncerError> {
        if !self.config.dogpile_config.enabled || self.is_tenant_paused(&candidate.target_did) {
            return Ok(None);
        }

        let is_synthetic_mentions = candidate.focal_post_uri.ends_with("/_mentions");
        let mut fetch_uris = Vec::with_capacity(1 + candidate.recent_quote_uris.len());
        if !is_synthetic_mentions {
            fetch_uris.push(candidate.focal_post_uri.clone());
        }
        for qt_uri in &candidate.recent_quote_uris {
            if !fetch_uris.contains(qt_uri) {
                fetch_uris.push(qt_uri.clone());
            }
        }

        let snapshots = if fetch_uris.is_empty() {
            Vec::new()
        } else {
            self.enricher.fetch_post_engagements(&fetch_uris).await
        };

        let mut focal_post: Option<PostEngagementSnapshot> = None;
        let mut quote_snaps: Vec<PostEngagementSnapshot> = Vec::new();
        for snap in snapshots {
            if snap.uri == candidate.focal_post_uri {
                focal_post = Some(snap);
            } else {
                quote_snaps.push(snap);
            }
        }

        quote_snaps.sort_by(|a, b| {
            let score_a = a
                .like_count
                .saturating_add(a.repost_count.saturating_mul(2));
            let score_b = b
                .like_count
                .saturating_add(b.repost_count.saturating_mul(2));
            score_b.cmp(&score_a)
        });

        let target_followers = self
            .enricher
            .fetch_actor_followers_count(&candidate.target_did)
            .await;

        let mut metrics = candidate.initial_metrics.clone();
        if let Some(ref fp) = focal_post {
            metrics.direct_ratio = compute_direct_ratio(
                fp.reply_count,
                fp.quote_count,
                fp.like_count,
                fp.repost_count,
            );
        }

        let root_likes = focal_post.as_ref().map_or(0, |f| f.like_count);
        let mut top_catalyst: Option<CatalystInfo> = None;
        if let Some(top) = quote_snaps.first_mut() {
            let cat_followers = if top.author_followers.is_some() {
                top.author_followers
            } else {
                let fetched = self
                    .enricher
                    .fetch_actor_followers_count(&top.author_did)
                    .await;
                top.author_followers = fetched;
                fetched
            };
            let dunk = compute_dunk_ratio(top.like_count, root_likes);
            let asym = compute_power_asymmetry(cat_followers, target_followers);
            metrics.dunk_ratio = dunk;
            metrics.power_asymmetry = asym;

            top_catalyst = Some(CatalystInfo {
                post_uri: top.uri.clone(),
                author_did: top.author_did.clone(),
                author_handle: top.author_handle.clone(),
                author_followers: cat_followers,
                like_count: top.like_count,
                repost_count: top.repost_count,
                quote_count: top.quote_count,
                dunk_ratio: dunk,
                text_snippet: top.text.chars().take(200).collect(),
            });
        }

        metrics.structural_score = compute_structural_score(&metrics, &self.config.dogpile_config);
        metrics.composite_score = metrics.structural_score;

        if metrics.structural_score < self.config.dogpile_config.structural_trigger_score {
            return Ok(None);
        }

        let target_handle = match self.cached_handle_for_did(&candidate.target_did) {
            Some(h) => Some(h),
            None => self.resolve_did_to_handle(&candidate.target_did).await,
        };

        let stance: Option<StormStanceVerdict> = if self.config.dogpile_config.enable_llm_stance {
            let input = StormStanceInput {
                target_did: candidate.target_did.clone(),
                target_handle: target_handle.clone(),
                focal_post_uri: candidate.focal_post_uri.clone(),
                focal_post: focal_post.clone(),
                top_quotes: quote_snaps.iter().take(3).cloned().collect(),
                sample_replies: candidate.sample_replies.clone(),
                metrics: metrics.clone(),
            };
            match self.storm_stance_classifier.classify_storm(&input).await {
                Ok(verdict) => Some(verdict),
                Err(e) => {
                    tracing::debug!(
                        target = %candidate.target_did,
                        focal = %candidate.focal_post_uri,
                        error = %e,
                        "Stage 3 storm stance check unavailable; falling back to structural score"
                    );
                    Some(StormStanceVerdict::new(
                        false,
                        0.0,
                        "structural_only",
                        "LLM stance unavailable; using structural scoring fallback",
                        "structural_fallback",
                    ))
                }
            }
        } else {
            None
        };

        let used_llm = stance
            .as_ref()
            .is_some_and(|s| s.evaluator != "structural_fallback");
        metrics.composite_score =
            compute_composite_score(metrics.structural_score, stance.as_ref());

        let confirmed = if used_llm {
            metrics.composite_score >= self.config.dogpile_config.confirmed_score_threshold
        } else {
            metrics.structural_score >= self.config.dogpile_config.structural_fallback_threshold
        };

        if !confirmed {
            tracing::debug!(
                target = %candidate.target_did,
                focal = %candidate.focal_post_uri,
                structural = %metrics.structural_score,
                composite = %metrics.composite_score,
                "Surge candidate suppressed after Stage 2/3 verification"
            );
            return Ok(None);
        }

        let severity = severity_from_score(metrics.composite_score);
        let focal_post_snippet: String = focal_post
            .as_ref()
            .map(|f| f.text.chars().take(200).collect())
            .unwrap_or_default();

        let mut catalyst_qt_uris: Vec<String> =
            quote_snaps.iter().map(|q| q.uri.clone()).take(15).collect();
        for u in &candidate.recent_quote_uris {
            if catalyst_qt_uris.len() >= 15 {
                break;
            }
            if !catalyst_qt_uris.contains(u) {
                catalyst_qt_uris.push(u.clone());
            }
        }

        let existed = self
            .cache
            .get_active_storm_by_focal_uri(&candidate.target_did, &candidate.focal_post_uri)?
            .is_some();

        let event = StormEvent {
            id: 0,
            target_did: candidate.target_did.clone(),
            target_handle,
            focal_post_uri: candidate.focal_post_uri.clone(),
            focal_post_snippet,
            status: StormStatus::Active,
            severity,
            started_at_us: candidate.observed_at_us,
            updated_at_us: candidate.observed_at_us,
            resolved_at_us: None,
            metrics,
            top_catalyst,
            catalyst_qt_uris,
            stance,
            bounces_during_storm: 0,
            threadgate_applied: false,
            postgate_detaches_applied: 0,
        };

        let storm_id = self.cache.upsert_active_storm(&event)?;
        let persisted = self.cache.get_storm(storm_id)?.unwrap_or(StormEvent {
            id: storm_id,
            ..event
        });

        if !existed {
            self.stats.dogpiles_detected.fetch_add(1, Ordering::Relaxed);
        }

        let (should_emit, is_escalation) = self.dogpile_tracker.activate_storm(
            &candidate.target_did,
            &candidate.focal_post_uri,
            storm_id,
            severity,
            candidate.observed_at_us,
        );

        if should_emit {
            self.stats
                .storm_alerts_emitted
                .fetch_add(1, Ordering::Relaxed);
            info!(
                storm_id,
                target = %candidate.target_did,
                focal = %candidate.focal_post_uri,
                severity = %severity,
                is_escalation,
                composite = %persisted.metrics.composite_score,
                "🌪️ Confirmed dogpile storm; Storm Mode activated"
            );
            let _ = self.storm_notifier.send(StormNotification {
                storm: persisted.clone(),
                is_escalation,
            });
        }

        Ok(Some(persisted))
    }

    /// Expires stale storms/manual toggles and flushes due Storm Mode bounce digests.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if resolving expired storms in SQLite fails.
    pub fn flush_storm_maintenance(&self) -> Result<(), SkybouncerError> {
        let now_us = current_time_us();
        let (expired, digests) = self.dogpile_tracker.prune_and_expire(now_us);
        for (target_did, _focal_uri, storm_id) in expired {
            let _ = self.cache.update_storm_status(
                Some(&target_did),
                storm_id,
                StormStatus::Resolved,
                Some(now_us),
            );
        }
        for digest in digests {
            let _ = self.storm_digest_notifier.send(digest);
        }
        Ok(())
    }

    /// Lists dogpile storm events optionally scoped to `target_did`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite querying fails.
    pub fn list_storms_for(
        &self,
        target_did: Option<&str>,
        active_only: bool,
        limit: usize,
    ) -> Result<Vec<StormEvent>, SkybouncerError> {
        self.cache.list_storms(target_did, active_only, limit)
    }

    /// Returns the most recently updated active storm for `target_did`, if any.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite querying fails.
    pub fn get_latest_active_storm_for(
        &self,
        target_did: &str,
    ) -> Result<Option<StormEvent>, SkybouncerError> {
        self.cache.get_latest_active_storm_for(target_did)
    }

    /// Returns `true` if Storm Mode is currently active for `target_did`.
    #[must_use]
    pub fn is_storm_mode_active(&self, target_did: &str) -> bool {
        self.dogpile_tracker
            .is_storm_mode_active(target_did, current_time_us())
    }

    /// Manually activates or deactivates Storm Mode for `target_did`.
    pub fn set_storm_mode(&self, target_did: &str, enabled: bool) {
        let now_us = current_time_us();
        self.dogpile_tracker
            .set_manual_storm_mode(target_did, enabled, now_us);
        if !enabled {
            let _ = self.flush_storm_maintenance();
        }
    }

    /// Dismisses an active storm by ID (optionally verifying ownership by `target_did`).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] on cache failure or [`SkybouncerError::Config`]
    /// if a non-admin attempts to dismiss another user's storm.
    pub fn dismiss_storm(
        &self,
        caller_target_did: Option<&str>,
        storm_id: i64,
    ) -> Result<bool, SkybouncerError> {
        let Some(storm) = self.cache.get_storm(storm_id)? else {
            return Ok(false);
        };
        if let Some(required_did) = caller_target_did {
            if storm.target_did != required_did {
                return Err(SkybouncerError::Config(
                    "Access denied: you may only dismiss storms on your own account".to_string(),
                ));
            }
        }
        let updated = self.cache.update_storm_status(
            Some(&storm.target_did),
            storm_id,
            StormStatus::Dismissed,
            Some(current_time_us()),
        )?;
        self.dogpile_tracker
            .dismiss_storm(&storm.target_did, storm_id);
        Ok(updated)
    }

    /// Resolves a user-supplied post AT-URI, Bluesky web URL (including `@handle` URLs),
    /// or bare `rkey` while strictly verifying ownership by `protected_did`.
    async fn resolve_owned_post_uri(
        &self,
        protected_did: &str,
        post_uri_or_rkey: &str,
    ) -> Result<(String, String), SkybouncerError> {
        match parse_owned_post_uri(protected_did, post_uri_or_rkey) {
            Ok(pair) => Ok(pair),
            Err(orig_err) => {
                let trimmed = post_uri_or_rkey.trim();
                if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
                    if let Ok(parsed) = url::Url::parse(trimmed) {
                        let segments: Vec<&str> = parsed
                            .path_segments()
                            .map(|s| s.filter(|p| !p.is_empty()).collect())
                            .unwrap_or_default();
                        if segments.len() == 4
                            && segments[0] == "profile"
                            && segments[2] == "post"
                            && !segments[1].starts_with("did:")
                        {
                            let actor = segments[1];
                            let rkey = segments[3];
                            if let Some(resolved_did) = self.resolve_handle(actor).await {
                                let candidate =
                                    format!("at://{resolved_did}/app.bsky.feed.post/{rkey}");
                                return parse_owned_post_uri(protected_did, &candidate);
                            }
                        }
                    }
                }
                Err(orig_err)
            }
        }
    }

    /// Applies an `app.bsky.feed.threadgate` reply lock on `protected_did`'s post.
    ///
    /// Returns `(threadgate_uri, canonical_post_uri)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] on ownership violation, OAuth failure, or PDS error.
    pub async fn lock_thread(
        &self,
        protected_did: &str,
        post_uri_or_rkey: &str,
        policy: ThreadgatePolicy,
    ) -> Result<(String, String), SkybouncerError> {
        let (canonical_post_uri, _) = self
            .resolve_owned_post_uri(protected_did, post_uri_or_rkey)
            .await?;
        let tg_uri = self
            .with_pds_client_401_retry(protected_did, |pds_client| {
                let post_uri_ref = canonical_post_uri.as_str();
                async move {
                    apply_threadgate(
                        &pds_client,
                        protected_did,
                        post_uri_ref,
                        policy,
                        self.config.dry_run,
                    )
                    .await
                }
            })
            .await
            .inspect_err(|_| {
                self.stats
                    .errors_encountered
                    .fetch_add(1, Ordering::Relaxed);
            })?;
        self.stats
            .threadgates_applied
            .fetch_add(1, Ordering::Relaxed);
        let _ = self
            .cache
            .mark_storm_threadgate_applied(protected_did, &canonical_post_uri, true);
        Ok((tg_uri, canonical_post_uri))
    }

    /// Removes an `app.bsky.feed.threadgate` reply lock from `protected_did`'s post.
    ///
    /// Returns the canonical post AT-URI.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] on ownership violation, OAuth failure, or PDS error.
    pub async fn unlock_thread(
        &self,
        protected_did: &str,
        post_uri_or_rkey: &str,
    ) -> Result<String, SkybouncerError> {
        let (canonical_post_uri, _) = self
            .resolve_owned_post_uri(protected_did, post_uri_or_rkey)
            .await?;
        self.with_pds_client_401_retry(protected_did, |pds_client| {
            let post_uri_ref = canonical_post_uri.as_str();
            async move {
                remove_threadgate(
                    &pds_client,
                    protected_did,
                    post_uri_ref,
                    self.config.dry_run,
                )
                .await
            }
        })
        .await
        .inspect_err(|_| {
            self.stats
                .errors_encountered
                .fetch_add(1, Ordering::Relaxed);
        })?;
        let _ = self
            .cache
            .mark_storm_threadgate_applied(protected_did, &canonical_post_uri, false);
        Ok(canonical_post_uri)
    }

    /// Detaches quote-posts (and/or disables all quotes) on `protected_did`'s post via
    /// `app.bsky.feed.postgate`.
    ///
    /// When `qt_uris` is empty/absent and `disable_all_quotes` is `false`, automatically
    /// targets any catalyst quote-post URIs stored on the corresponding storm record.
    /// Returns `(postgate_uri, canonical_post_uri, total_detached_count)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] on ownership violation, missing targets, or PDS error.
    pub async fn detach_quotes(
        &self,
        protected_did: &str,
        post_uri_or_rkey: &str,
        qt_uris: Option<&[String]>,
        disable_all_quotes: bool,
    ) -> Result<(String, String, usize), SkybouncerError> {
        let (canonical_post_uri, _) = self
            .resolve_owned_post_uri(protected_did, post_uri_or_rkey)
            .await?;

        let mut effective_qts: Vec<String> = qt_uris
            .unwrap_or(&[])
            .iter()
            .map(|u| u.trim().to_string())
            .filter(|u| u.starts_with("at://"))
            .collect();

        if effective_qts.is_empty() && !disable_all_quotes {
            if let Some(storm) = self
                .cache
                .get_active_storm_by_focal_uri(protected_did, &canonical_post_uri)?
            {
                effective_qts = storm.catalyst_qt_uris;
            } else if let Ok(storms) = self.cache.list_storms(Some(protected_did), false, 20) {
                if let Some(found) = storms
                    .into_iter()
                    .find(|s| s.focal_post_uri == canonical_post_uri)
                {
                    effective_qts = found.catalyst_qt_uris;
                }
            }
        }

        if effective_qts.is_empty() && !disable_all_quotes {
            return Err(SkybouncerError::Config(
                "No catalyst quote-post URIs found for this post; provide qt_uris or enable disable_all_quotes"
                    .to_string(),
            ));
        }

        let (pg_uri, total_detached) = self
            .with_pds_client_401_retry(protected_did, |pds_client| {
                let post_uri_ref = canonical_post_uri.as_str();
                let qts_ref = &effective_qts;
                async move {
                    apply_postgate_detach(
                        &pds_client,
                        protected_did,
                        post_uri_ref,
                        qts_ref,
                        disable_all_quotes,
                        self.config.dry_run,
                    )
                    .await
                }
            })
            .await
            .inspect_err(|_| {
                self.stats
                    .errors_encountered
                    .fetch_add(1, Ordering::Relaxed);
            })?;

        let applied_delta =
            u64::try_from(effective_qts.len().max(usize::from(disable_all_quotes))).unwrap_or(1);
        self.stats
            .postgate_detaches_applied
            .fetch_add(applied_delta, Ordering::Relaxed);
        let _ = self.cache.increment_storm_postgate_detaches(
            protected_did,
            &canonical_post_uri,
            applied_delta,
        );

        Ok((pg_uri, canonical_post_uri, total_detached))
    }
}
