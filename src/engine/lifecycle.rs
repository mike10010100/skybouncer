use super::*;

impl SkybouncerEngine {
    /// Runs the pipeline event processing loop reading from `rx` until cancelled.
    ///
    /// Commits from Jetstream are ingested on the fast path without blocking. Surviving
    /// candidate interactions are enqueued into a decoupled bounded evaluation channel,
    /// where background worker(s) evaluate candidates against the primary classifier model
    /// at controlled concurrency (`config.evaluation_concurrency`).
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if unrecoverable pipeline failure occurs.
    pub async fn run(
        &self,
        mut rx: mpsc::Receiver<JetstreamCommit>,
        cancel: CancellationToken,
    ) -> Result<EngineStatsSnapshot, SkybouncerError> {
        let queue_capacity = self.config.evaluation_queue_capacity.max(100);
        let (eval_tx, mut eval_rx) = mpsc::channel::<Interaction>(queue_capacity);
        let (fast_action_tx, mut fast_action_rx) =
            mpsc::channel::<(Interaction, Verdict, bool)>(queue_capacity);
        let (storm_tx, mut storm_rx) = mpsc::channel::<crate::dogpile::SurgeCandidate>(64);
        let concurrency = self.config.evaluation_concurrency.max(1);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let action_semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(4)));

        let eval_engine = self.clone();
        let eval_cancel = cancel.clone();
        let mut eval_tasks = JoinSet::new();

        // Spawn background evaluation worker (stops dequeuing new items once cancelled,
        // allowing already in-flight evaluations and PDS writes to finish cleanly).
        let queue_worker = async move {
            let mut active_evals = JoinSet::new();

            loop {
                let permit = tokio::select! {
                    biased;
                    _ = eval_cancel.cancelled() => break,
                    res = semaphore.clone().acquire_owned() => match res {
                        Ok(p) => p,
                        Err(_) => break,
                    }
                };
                let candidate = tokio::select! {
                    biased;
                    _ = eval_cancel.cancelled() => {
                        drop(permit);
                        break;
                    }
                    res = eval_rx.recv() => match res {
                        Some(c) => c,
                        None => {
                            drop(permit);
                            break;
                        }
                    }
                };
                let eng = eval_engine.clone();
                let task_cancel = eval_cancel.clone();
                active_evals.spawn(async move {
                    let _permit = permit;
                    let res = eng.evaluate_candidate_queued(candidate, &task_cancel).await;
                    eng.stats
                        .eval_queue_processed
                        .fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = res {
                        warn!(error = %e, "Background candidate evaluation failed");
                    }
                });

                while let Some(res) = active_evals.try_join_next() {
                    let _ = res;
                }
            }

            // Drain remaining active in-flight evaluations
            while let Some(res) = active_evals.join_next().await {
                let _ = res;
            }
        };

        eval_tasks.spawn(queue_worker);

        // Spawn deferred fast-path remote action worker (eval cache hits & heuristic bounces)
        let action_engine = self.clone();
        let action_cancel = cancel.clone();
        let fast_action_worker = async move {
            let mut active_actions = JoinSet::new();

            loop {
                let permit = tokio::select! {
                    biased;
                    _ = action_cancel.cancelled() => break,
                    res = action_semaphore.clone().acquire_owned() => match res {
                        Ok(p) => p,
                        Err(_) => break,
                    }
                };
                let (interaction, verdict, is_heuristic) = tokio::select! {
                    biased;
                    _ = action_cancel.cancelled() => {
                        drop(permit);
                        break;
                    }
                    res = fast_action_rx.recv() => match res {
                        Some(item) => item,
                        None => {
                            drop(permit);
                            break;
                        }
                    }
                };
                let eng = action_engine.clone();
                active_actions.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = eng
                        .execute_deferred_action(interaction, verdict, is_heuristic)
                        .await
                    {
                        warn!(error = %e, "Background fast-path PDS action failed");
                    }
                });

                while let Some(res) = active_actions.try_join_next() {
                    let _ = res;
                }
            }

            while let Some(res) = active_actions.join_next().await {
                let _ = res;
            }
        };

        eval_tasks.spawn(fast_action_worker);

        // Spawn decoupled dogpile surge enrichment & stance worker (bounded concurrency = 2)
        let storm_engine = self.clone();
        let storm_cancel = cancel.clone();
        let storm_semaphore = Arc::new(tokio::sync::Semaphore::new(2));
        let storm_worker = async move {
            let mut active_storms = JoinSet::new();
            loop {
                let permit = tokio::select! {
                    biased;
                    _ = storm_cancel.cancelled() => break,
                    res = storm_semaphore.clone().acquire_owned() => match res {
                        Ok(p) => p,
                        Err(_) => break,
                    }
                };
                let candidate = tokio::select! {
                    biased;
                    _ = storm_cancel.cancelled() => {
                        drop(permit);
                        break;
                    }
                    res = storm_rx.recv() => match res {
                        Some(c) => c,
                        None => {
                            drop(permit);
                            break;
                        }
                    }
                };
                let eng = storm_engine.clone();
                active_storms.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = eng.evaluate_storm_candidate(candidate).await {
                        warn!(error = %e, "Background storm candidate evaluation failed");
                    }
                });
                while let Some(res) = active_storms.try_join_next() {
                    let _ = res;
                }
            }
            while let Some(res) = active_storms.join_next().await {
                let _ = res;
            }
        };
        eval_tasks.spawn(storm_worker);

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    debug!("Engine processing loop received cancellation; exiting loop immediately");
                    break;
                }
                commit_opt = rx.recv() => {
                    match commit_opt {
                        Some(commit) => {
                            let _ = self
                                .process_commit_queued_with_storms(
                                    &commit,
                                    &eval_tx,
                                    Some(&storm_tx),
                                    Some(&fast_action_tx),
                                )
                                .await;
                        }
                        None => {
                            debug!("Commit channel closed; shutting down engine loop");
                            break;
                        }
                    }
                }
            }
        }

        // Drop senders so workers drain in-flight tasks and exit cleanly
        drop(eval_tx);
        drop(fast_action_tx);
        drop(storm_tx);

        // Wait for queue worker to finish draining (bounded by shutdown timeout)
        let drain_future = async {
            while let Some(res) = eval_tasks.join_next().await {
                let _ = res;
            }
        };

        if tokio::time::timeout(DEFAULT_SHUTDOWN_TIMEOUT, drain_future)
            .await
            .is_err()
        {
            warn!("Evaluation queue worker drain timed out; aborting background evaluations");
            eval_tasks.abort_all();
            while eval_tasks.join_next().await.is_some() {}
        }

        Ok(self.stats.snapshot())
    }

    /// Runs the pipeline event processing loop (alias for [`Self::run`]).
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if unrecoverable pipeline failure occurs.
    pub async fn run_pipeline(
        &self,
        rx: mpsc::Receiver<JetstreamCommit>,
        cancel: CancellationToken,
    ) -> Result<EngineStatsSnapshot, SkybouncerError> {
        self.run(rx, cancel).await
    }

    /// Prunes expired temporary bounces from both sovereign PDS moderation lists and the SQLite cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if querying expired bounces fails.
    pub async fn prune_expired_bounces(&self) -> Result<usize, SkybouncerError> {
        let cancel = CancellationToken::new();
        self.prune_expired_bounces_with_cancel(&cancel).await
    }

    /// Cancellable variant of [`Self::prune_expired_bounces`].
    ///
    /// Skips tenants currently flagged `reauth_required` to avoid redundant OAuth refresh storms.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if querying expired bounces fails.
    pub async fn prune_expired_bounces_with_cancel(
        &self,
        cancel: &CancellationToken,
    ) -> Result<usize, SkybouncerError> {
        if cancel.is_cancelled() {
            return Ok(0);
        }
        let now_us = current_time_us();
        let cache = Arc::clone(&self.cache);
        let expired = tokio::task::spawn_blocking(move || cache.list_expired_bounces(now_us))
            .await
            .map_err(|e| {
                SkybouncerError::Database(format!("prune_expired_bounces join error: {e}"))
            })??;
        if expired.is_empty() {
            return Ok(0);
        }

        let mut pruned_count = 0;
        for record in expired {
            if cancel.is_cancelled() {
                break;
            }
            if self
                .tenant_registry
                .is_reauth_required(&record.protected_did)
                .unwrap_or(false)
            {
                debug!(
                    protected_did = %record.protected_did,
                    "Skipping expired bounce prune for tenant requiring re-authentication"
                );
                continue;
            }
            match self
                .pardon_user(&record.protected_did, &record.subject_did)
                .await
            {
                Ok(true) => {
                    pruned_count += 1;
                    info!(
                        subject_did = %record.subject_did,
                        protected_did = %record.protected_did,
                        "Pruned expired temporary bounce from PDS and cache"
                    );
                }
                Ok(false) => {
                    debug!(
                        subject_did = %record.subject_did,
                        protected_did = %record.protected_did,
                        "Expired bounce record was already removed"
                    );
                }
                Err(e) => {
                    warn!(
                        subject_did = %record.subject_did,
                        protected_did = %record.protected_did,
                        error = %e,
                        "Failed to pardon expired bounce on PDS"
                    );
                }
            }
        }

        Ok(pruned_count)
    }

    /// Runs the periodic background maintenance loop to prune expired evaluation cache entries.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if cache maintenance fails.
    pub async fn run_maintenance(
        &self,
        interval_dur: Duration,
        cancel: CancellationToken,
    ) -> Result<usize, SkybouncerError> {
        const RETENTION_90D_US: u64 = 90u64 * 86_400 * 1_000_000;
        let mut interval = tokio::time::interval(interval_dur);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut total_pruned: usize = 0;
        let mut tick_count: u64 = 0;

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    tick_count = tick_count.saturating_add(1);
                    let run_vacuum = tick_count.is_multiple_of(12);
                    let eng = self.clone();
                    let db_res = tokio::task::spawn_blocking(move || {
                        let mut pruned_eval = 0usize;
                        match eng.cache.prune_expired_evaluations() {
                            Ok(pruned) => {
                                pruned_eval = pruned;
                                debug!(pruned, "Pruned expired evaluations from cache");
                            }
                            Err(e) => {
                                warn!(error = %e, "Failed to prune expired evaluations in maintenance task");
                            }
                        }
                        if let Err(e) = eng.persist_stats() {
                            warn!(error = %e, "Failed to persist dashboard telemetry counters in maintenance task");
                        }
                        match eng.tenant_registry.prune_expired_web_sessions() {
                            Ok(count) if count > 0 => {
                                debug!(count, "Pruned expired web sessions");
                            }
                            Ok(_) => {}
                            Err(e) => {
                                warn!(error = %e, "Failed to prune expired web sessions in maintenance task");
                            }
                        }
                        let now_us = current_time_us();
                        let did_handle_cutoff = now_us.saturating_sub(
                            u64::try_from(DEFAULT_DID_HANDLE_CACHE_TTL.as_micros()).unwrap_or(u64::MAX),
                        );
                        match eng
                            .cache
                            .prune_did_handles(did_handle_cutoff, DEFAULT_DID_HANDLE_CACHE_MAX_ENTRIES)
                        {
                            Ok(count) if count > 0 => {
                                debug!(count, "Pruned stale DID-to-handle cache entries");
                            }
                            Ok(_) => {}
                            Err(e) => {
                                warn!(error = %e, "Failed to prune DID-to-handle cache in maintenance task");
                            }
                        }
                        let retention_cutoff = now_us.saturating_sub(RETENTION_90D_US);
                        if let Err(e) = eng.cache.prune_resolved_storms(retention_cutoff) {
                            warn!(error = %e, "Failed to prune resolved dogpile storms in maintenance task");
                        }
                        if let Err(e) = eng.cache.prune_bounce_history(retention_cutoff) {
                            warn!(error = %e, "Failed to prune old bounce history in maintenance task");
                        }
                        if let Err(e) = eng.flush_storm_maintenance() {
                            warn!(error = %e, "Failed to flush storm maintenance in maintenance task");
                        }
                        if run_vacuum {
                            if let Err(e) = eng.cache.run_incremental_vacuum_and_optimize(64) {
                                warn!(error = %e, "Failed to run SQLite incremental_vacuum/optimize");
                            }
                        }
                        pruned_eval
                    })
                    .await;
                    match db_res {
                        Ok(pruned) => {
                            total_pruned = total_pruned.saturating_add(pruned);
                        }
                        Err(e) => {
                            warn!(error = %e, "Maintenance blocking task failed");
                        }
                    }

                    self.rate_limiter.prune_stale();
                    self.prune_handle_cache();

                    if cancel.is_cancelled() {
                        break;
                    }
                    match self.prune_expired_bounces_with_cancel(&cancel).await {
                        Ok(count) if count > 0 => {
                            info!(count, "Pruned expired temporary bounces from PDS and cache");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!(error = %e, "Failed to prune expired bounces in maintenance task");
                        }
                    }

                    if cancel.is_cancelled() {
                        break;
                    }
                    let refreshed = self.refresh_expiring_tenant_sessions_with_cancel(&cancel).await;
                    if refreshed > 0 {
                        info!(
                            refreshed,
                            "Proactively refreshed expiring tenant OAuth sessions in maintenance task"
                        );
                    }
                }
            }
        }

        Ok(total_pruned)
    }

    /// Spawns the pipeline worker into a managed [`JoinSet`], returning an MPSC sender for commits.
    pub fn spawn_in_join_set(
        &self,
        join_set: &mut JoinSet<Result<EngineStatsSnapshot, SkybouncerError>>,
        cancel: CancellationToken,
    ) -> mpsc::Sender<JetstreamCommit> {
        let (tx, rx) = mpsc::channel(self.config.channel_capacity);
        let engine = self.clone();
        join_set.spawn(async move { engine.run(rx, cancel).await });
        tx
    }

    /// Gracefully drains in-flight tasks in a [`JoinSet`] with bounded timeout abort.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if shutdown coordination fails.
    pub async fn drain_and_shutdown<T: 'static>(
        join_set: &mut JoinSet<T>,
        cancel: &CancellationToken,
        timeout: Duration,
    ) -> Result<(), SkybouncerError> {
        cancel.cancel();
        let drain_future = async {
            while let Some(res) = join_set.join_next().await {
                let _ = res;
            }
        };

        if tokio::time::timeout(timeout, drain_future).await.is_err() {
            warn!(
                timeout = ?timeout,
                "Engine shutdown timed out; aborting remaining background tasks"
            );
            join_set.abort_all();
            while join_set.join_next().await.is_some() {}
        }

        Ok(())
    }
}
