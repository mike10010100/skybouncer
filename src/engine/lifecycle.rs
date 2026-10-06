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
        let concurrency = self.config.evaluation_concurrency.max(1);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));

        let eval_engine = self.clone();
        let mut eval_tasks = JoinSet::new();

        // Spawn background evaluation worker
        let queue_worker = async move {
            let mut active_evals = JoinSet::new();

            while let Ok(permit) = semaphore.clone().acquire_owned().await {
                match eval_rx.recv().await {
                    Some(candidate) => {
                        let eng = eval_engine.clone();
                        active_evals.spawn(async move {
                            let _permit = permit;
                            eng.stats
                                .eval_queue_processed
                                .fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = eng.evaluate_candidate(candidate).await {
                                warn!(error = %e, "Background candidate evaluation failed");
                            }
                        });
                    }
                    None => {
                        // Channel closed (eval_tx dropped) and empty
                        drop(permit);
                        break;
                    }
                }

                while let Some(res) = active_evals.try_join_next() {
                    let _ = res;
                }
            }

            // Drain remaining active evaluations
            while let Some(res) = active_evals.join_next().await {
                let _ = res;
            }
        };

        eval_tasks.spawn(queue_worker);

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    debug!("Engine processing loop received cancellation; draining buffered commits");
                    while let Ok(commit) = rx.try_recv() {
                        let _ = self.process_commit_queued(&commit, &eval_tx).await;
                    }
                    break;
                }
                commit_opt = rx.recv() => {
                    match commit_opt {
                        Some(commit) => {
                            let _ = self.process_commit_queued(&commit, &eval_tx).await;
                        }
                        None => {
                            debug!("Commit channel closed; shutting down engine loop");
                            break;
                        }
                    }
                }
            }
        }

        // Drop eval_tx so queue worker receives None after draining remaining queue items
        drop(eval_tx);

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
        let now_us = current_time_us();
        let expired = self.cache.list_expired_bounces(now_us)?;
        if expired.is_empty() {
            return Ok(0);
        }

        let mut pruned_count = 0;
        for record in expired {
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
        let mut interval = tokio::time::interval(interval_dur);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut total_pruned: usize = 0;

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    match self.cache.prune_expired_evaluations() {
                        Ok(pruned) => {
                            total_pruned = total_pruned.saturating_add(pruned);
                            debug!(pruned, "Pruned expired evaluations from cache");
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to prune expired evaluations in maintenance task");
                        }
                    }
                    if let Err(e) = self.persist_stats() {
                        warn!(error = %e, "Failed to persist dashboard telemetry counters in maintenance task");
                    }
                    self.rate_limiter.prune_stale();
                    match self.tenant_registry.prune_expired_web_sessions() {
                        Ok(count) => {
                            if count > 0 {
                                debug!(count, "Pruned expired web sessions");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to prune expired web sessions in maintenance task");
                        }
                    }
                    match self.prune_expired_bounces().await {
                        Ok(count) => {
                            if count > 0 {
                                info!(count, "Pruned expired temporary bounces from PDS and cache");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to prune expired bounces in maintenance task");
                        }
                    }
                    let now_us = current_time_us();
                    let did_handle_cutoff = now_us.saturating_sub(
                        u64::try_from(DEFAULT_DID_HANDLE_CACHE_TTL.as_micros()).unwrap_or(u64::MAX),
                    );
                    match self
                        .cache
                        .prune_did_handles(did_handle_cutoff, DEFAULT_DID_HANDLE_CACHE_MAX_ENTRIES)
                    {
                        Ok(count) => {
                            if count > 0 {
                                debug!(count, "Pruned stale DID-to-handle cache entries");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to prune DID-to-handle cache in maintenance task");
                        }
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
