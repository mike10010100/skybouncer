//! Sovereign ATProto moderation list manager coordinating cache-first provisioning,
//! violator bouncing, and pardons across SQLite cache and PDS repository client.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::Deserialize;
use skybase::repo::PdsRepoClient;
use tracing::{debug, error, info, instrument, warn};

use crate::classifier::{RuleRubric, ViolationCategory};
use crate::error::SkybouncerError;
use crate::modlist::cache::{BouncedUser, DeduplicationCache, ModListConfig};
use crate::types::{
    now_iso8601, ListBlockRecord, ListItemRecord, ListRecordsResponse, ModListRecord,
};

/// Default name assigned to newly provisioned moderation lists.
pub const DEFAULT_MOD_LIST_NAME: &str = "Skybouncer Moderation List";

/// Default description assigned to newly provisioned moderation lists.
pub const DEFAULT_MOD_LIST_DESCRIPTION: &str =
    "Automated sovereign moderation list maintained by Skybouncer.";

/// Number of lock shards for striped async in-flight synchronization.
///
/// 64 shards aligns with the repository concurrency standard (`GraphStore`,
/// `ImpressionStore`), providing optimal distribution with ~2KB fixed memory footprint.
pub const NUM_LOCK_SHARDS: usize = 64;

/// Sharded async mutex pool providing lock striping partitioned by string key.
///
/// Guarantees that concurrent operations targeting the same key (e.g. protected DID or
/// violator DID) synchronize on the same async mutex, eliminating TOCTOU races across
/// `.await` points without dynamic heap allocations or memory leaks.
#[derive(Debug)]
pub struct StripedAsyncLocks {
    shards: Box<[tokio::sync::Mutex<()>]>,
}

impl StripedAsyncLocks {
    /// Creates a new striped async lock pool with [`NUM_LOCK_SHARDS`] shards.
    #[must_use]
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(NUM_LOCK_SHARDS);
        for _ in 0..NUM_LOCK_SHARDS {
            shards.push(tokio::sync::Mutex::new(()));
        }
        Self {
            shards: shards.into_boxed_slice(),
        }
    }

    /// Selects the [`tokio::sync::Mutex`] shard corresponding to the given key.
    #[must_use]
    pub fn shard_for(&self, key: &str) -> &tokio::sync::Mutex<()> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();
        let idx = (hash as usize) % NUM_LOCK_SHARDS;
        &self.shards[idx]
    }
}

impl Default for StripedAsyncLocks {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level orchestration manager for sovereign ATProto moderation lists.
///
/// Encapsulates cache-first provisioning, violator bouncing, and unban/pardon operations.
/// Interacts with an embedded SQLite [`DeduplicationCache`] to eliminate duplicate PDS mutations
/// and redundant AI evaluations, enforcing sub-microsecond local drops.
///
/// Employs sharded async lock striping via [`StripedAsyncLocks`] to guarantee in-flight
/// deduplication, eliminating TOCTOU check-then-act races across `.await` points and
/// preventing duplicate PDS mutations or orphaned listitems under high concurrent load.
#[derive(Clone)]
pub struct ModListManager {
    cache: Arc<DeduplicationCache>,
    rubric: Arc<RwLock<Option<RuleRubric>>>,
    list_name: String,
    list_description: Option<String>,
    list_provision_locks: Arc<StripedAsyncLocks>,
    listblock_provision_locks: Arc<StripedAsyncLocks>,
    bounce_locks: Arc<StripedAsyncLocks>,
    dry_run: bool,
}

impl ModListManager {
    /// Creates a new `ModListManager` backed by a [`DeduplicationCache`] and optional [`RuleRubric`].
    #[must_use]
    pub fn new(cache: DeduplicationCache, rubric: Option<RuleRubric>) -> Self {
        Self {
            cache: Arc::new(cache),
            rubric: Arc::new(RwLock::new(rubric)),
            list_name: DEFAULT_MOD_LIST_NAME.to_string(),
            list_description: Some(DEFAULT_MOD_LIST_DESCRIPTION.to_string()),
            list_provision_locks: Arc::new(StripedAsyncLocks::new()),
            listblock_provision_locks: Arc::new(StripedAsyncLocks::new()),
            bounce_locks: Arc::new(StripedAsyncLocks::new()),
            dry_run: false,
        }
    }

    /// Creates a new `ModListManager` from a shared cache handle.
    #[must_use]
    pub fn from_shared_cache(cache: Arc<DeduplicationCache>) -> Self {
        Self {
            cache,
            rubric: Arc::new(RwLock::new(None)),
            list_name: DEFAULT_MOD_LIST_NAME.to_string(),
            list_description: Some(DEFAULT_MOD_LIST_DESCRIPTION.to_string()),
            list_provision_locks: Arc::new(StripedAsyncLocks::new()),
            listblock_provision_locks: Arc::new(StripedAsyncLocks::new()),
            bounce_locks: Arc::new(StripedAsyncLocks::new()),
            dry_run: false,
        }
    }

    /// Configures whether this manager runs in shadow dry-run mode (simulating PDS mutations).
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Returns `true` if this manager operates in shadow dry-run mode.
    #[must_use]
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Attaches an optional [`RuleRubric`] for sensitivity threshold validation.
    #[must_use]
    pub fn with_rubric(self, rubric: RuleRubric) -> Self {
        *self.rubric.write() = Some(rubric);
        self
    }

    /// Updates the active moderation rubric in real time.
    pub fn set_rubric(&self, rubric: RuleRubric) {
        *self.rubric.write() = Some(rubric);
    }

    /// Configures a custom name for newly provisioned moderation lists.
    #[must_use]
    pub fn with_list_name(mut self, name: impl Into<String>) -> Self {
        self.list_name = name.into();
        self
    }

    /// Configures a custom description for newly provisioned moderation lists.
    #[must_use]
    pub fn with_list_description(mut self, description: Option<String>) -> Self {
        self.list_description = description;
        self
    }

    /// Opens or creates a `ModListManager` backed by a SQLite database at the given path.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite initialization fails.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SkybouncerError> {
        let cache = DeduplicationCache::open(path)?;
        Ok(Self::new(cache, None))
    }

    /// Opens an isolated in-memory `ModListManager` (ideal for hermetic testing).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if in-memory SQLite initialization fails.
    pub fn open_in_memory() -> Result<Self, SkybouncerError> {
        let cache = DeduplicationCache::open_in_memory()?;
        Ok(Self::new(cache, None))
    }

    /// Returns a reference to the underlying [`DeduplicationCache`].
    #[must_use]
    pub fn cache(&self) -> &Arc<DeduplicationCache> {
        &self.cache
    }

    /// Returns a copy of the active [`RuleRubric`], if configured.
    #[must_use]
    pub fn rubric(&self) -> Option<RuleRubric> {
        self.rubric.read().clone()
    }

    /// Ensures that an ATProto moderation list (`app.bsky.graph.list` with
    /// `purpose: "app.bsky.graph.defs#modlist"`) exists for the given protected user.
    ///
    /// # Waterfall & Concurrency Architecture
    /// 1. **Fast cache-first check (unlocked)**: If already present in SQLite cache, returns cached
    ///    `list_uri` immediately (<100µs, $0 cost, 0 network calls).
    /// 2. **Striped async lock**: Synchronizes on the shard for `protected_did` to serialize
    ///    concurrent provisioning and prevent duplicate list creations on the PDS.
    /// 3. **Double-check cache (under lock)**: If a concurrent task finished provisioning while
    ///    waiting for the lock, returns the newly cached URI.
    /// 4. **Remote PDS discovery**: Queries remote PDS via `com.atproto.repo.listRecords`. If an
    ///    existing list with purpose `app.bsky.graph.defs#modlist` is discovered, caches it and
    ///    returns its URI.
    /// 5. **Provisioning**: Creates a new moderation list on the sovereign PDS via
    ///    `pds_client.create_record`, caches the resulting URI and CID, and returns the URI.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Repo`] if PDS record creation fails,
    /// or [`SkybouncerError::Database`] if cache access fails.
    #[instrument(skip(self, pds_client), fields(protected_did = %protected_did))]
    pub async fn ensure_mod_list(
        &self,
        pds_client: &PdsRepoClient,
        protected_did: &str,
    ) -> Result<String, SkybouncerError> {
        // 1. Fast cache-first lookup (lock-free path)
        if let Some(config) = self.cache.get_mod_list(protected_did)? {
            debug!(
                list_uri = %config.list_uri,
                "Found existing moderation list in SQLite cache"
            );
            let _ = self
                .ensure_list_blocked(pds_client, protected_did, &config.list_uri)
                .await;
            return Ok(config.list_uri);
        }

        // 2. Acquire shard async lock for this protected DID to serialize concurrent provisioning
        let shard = self.list_provision_locks.shard_for(protected_did);
        let _guard = shard.lock().await;

        // 3. Double-check cache under the lock: another task may have provisioned while we waited
        if let Some(config) = self.cache.get_mod_list(protected_did)? {
            debug!(
                list_uri = %config.list_uri,
                "Found moderation list provisioned by concurrent task in SQLite cache"
            );
            let _ = self
                .ensure_list_blocked(pds_client, protected_did, &config.list_uri)
                .await;
            return Ok(config.list_uri);
        }

        // 4. Query remote PDS com.atproto.repo.listRecords for existing modlist (skipped in dry-run)
        if self.dry_run {
            let simulated_uri = format!("at://{protected_did}/app.bsky.graph.list/shadow_modlist");
            let now_us = current_time_us();
            let config = ModListConfig {
                user_did: protected_did.to_string(),
                list_uri: simulated_uri.clone(),
                list_cid: "bafyreidryrunsimulatedlistcid0000000000000000000000000000".to_string(),
                created_at: now_us,
            };
            self.cache.set_mod_list(&config)?;
            info!(
                list_uri = %simulated_uri,
                "🛡️ [SHADOW MODE] Simulated moderation list on sovereign PDS"
            );
            let _ = self
                .ensure_list_blocked(pds_client, protected_did, &simulated_uri)
                .await;
            return Ok(simulated_uri);
        }

        let resp = self
            .list_pds_records::<ModListRecord>(pds_client, "app.bsky.graph.list", 50)
            .await?;

        for item in resp.records {
            if item.value.is_modlist() {
                info!(
                    list_uri = %item.uri,
                    "Discovered existing remote moderation list on PDS; caching locally"
                );
                let now_us = current_time_us();
                let config = ModListConfig {
                    user_did: protected_did.to_string(),
                    list_uri: item.uri.clone(),
                    list_cid: item.cid,
                    created_at: now_us,
                };
                self.cache.set_mod_list(&config)?;
                if let Err(e) = self
                    .ensure_list_blocked(pds_client, protected_did, &item.uri)
                    .await
                {
                    warn!(error = %e, protected_did = %protected_did, "Failed to ensure list blocked");
                }
                return Ok(item.uri);
            }
        }

        info!(
            protected_did = %protected_did,
            "Provisioning new ATProto moderation list on sovereign PDS"
        );

        // 5. Provision new list via pds_client.create_record
        let rkey = skybase::repo::generate_tid();
        let now_iso = now_iso8601();
        let now_us = current_time_us();

        let list_record =
            ModListRecord::new_modlist(&self.list_name, self.list_description.clone(), now_iso);

        let result = pds_client
            .create_record("app.bsky.graph.list", Some(&rkey), &list_record, true)
            .await
            .map_err(|e| {
                SkybouncerError::Repo(format!("Failed to create moderation list on PDS: {e}"))
            })?;

        info!(
            list_uri = %result.uri,
            list_cid = %result.cid,
            "Successfully provisioned moderation list on PDS"
        );

        let config = ModListConfig {
            user_did: protected_did.to_string(),
            list_uri: result.uri.clone(),
            list_cid: result.cid,
            created_at: now_us,
        };
        self.cache.set_mod_list(&config)?;
        if let Err(e) = self
            .ensure_list_blocked(pds_client, protected_did, &result.uri)
            .await
        {
            warn!(error = %e, protected_did = %protected_did, "Failed to ensure list blocked");
        }

        Ok(result.uri)
    }

    /// Ensures that an `app.bsky.graph.listblock` record exists on the protected user's PDS,
    /// activating automatic blocking for all violators placed on this moderation list.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Repo`] if PDS record creation fails,
    /// or [`SkybouncerError::Database`] if cache access fails.
    #[instrument(skip(self, pds_client), fields(protected_did = %protected_did, list_uri = %list_uri))]
    pub async fn ensure_list_blocked(
        &self,
        pds_client: &PdsRepoClient,
        protected_did: &str,
        list_uri: &str,
    ) -> Result<(), SkybouncerError> {
        // Fast path: already confirmed and cached locally
        if self.cache.is_list_blocked(protected_did)? {
            debug!(
                protected_did = %protected_did,
                list_uri = %list_uri,
                "Listblock auto-blocking is already active in SQLite cache"
            );
            return Ok(());
        }

        // Acquire shard async lock for this protected DID to serialize concurrent listblock setup
        let shard = self.listblock_provision_locks.shard_for(protected_did);
        let _guard = shard.lock().await;

        if self.cache.is_list_blocked(protected_did)? {
            return Ok(());
        }

        if self.dry_run {
            self.cache.set_list_blocked(protected_did, list_uri)?;
            info!(
                protected_did = %protected_did,
                list_uri = %list_uri,
                "🛡️ [SHADOW MODE] Simulated listblock auto-blocking subscription on sovereign PDS"
            );
            return Ok(());
        }

        // Check if remote PDS already has a listblock targeting this list_uri
        let resp = self
            .list_pds_records::<ListBlockRecord>(pds_client, "app.bsky.graph.listblock", 50)
            .await?;

        for item in resp.records {
            if item.value.subject == list_uri {
                info!(
                    protected_did = %protected_did,
                    list_uri = %list_uri,
                    "Discovered existing remote listblock on PDS; caching locally"
                );
                self.cache.set_list_blocked(protected_did, list_uri)?;
                return Ok(());
            }
        }

        info!(
            protected_did = %protected_did,
            list_uri = %list_uri,
            "Auto-subscribing sovereign PDS to listblock for automated defense"
        );

        let rkey = skybase::repo::generate_tid();
        let now_iso = now_iso8601();
        let block_record = ListBlockRecord::new(list_uri, now_iso);

        let _ = pds_client
            .create_record("app.bsky.graph.listblock", Some(&rkey), &block_record, true)
            .await
            .map_err(|e| {
                SkybouncerError::Repo(format!("Failed to auto-subscribe listblock on PDS: {e}"))
            })?;

        self.cache.set_list_blocked(protected_did, list_uri)?;

        info!(
            protected_did = %protected_did,
            list_uri = %list_uri,
            "Successfully activated auto-blocking listblock on sovereign PDS"
        );

        Ok(())
    }

    /// Bounces a violating account by adding an `app.bsky.graph.listitem` to the protected user's
    /// moderation list on their sovereign PDS and recording it in the deduplication cache.
    ///
    /// # Pipeline & Concurrency Architecture
    /// 1. **Rubric Threshold Check**: If a rubric is configured and the confidence score falls
    ///    below the required sensitivity threshold, drops the candidate and returns `Ok(None)`.
    /// 2. **Fast Deduplication Check (unlocked)**: Checks the SQLite cache to see if the user is
    ///    already bounced. If so, returns `Ok(None)` immediately ($0 cost, 0 network mutations).
    /// 3. **Striped Async Lock**: Synchronizes on the shard for `candidate_did` to serialize
    ///    in-flight mutations targeting the same violator.
    /// 4. **Double-Check Deduplication (under lock)**: Re-checks if the candidate was bounced by
    ///    a concurrent task while waiting for the lock. If so, short-circuits to `Ok(None)` with
    ///    zero additional PDS writes.
    /// 5. **ModList Provisioning**: Calls [`Self::ensure_mod_list`] to ensure the parent list exists.
    /// 6. **PDS Mutation**: Issues a DPoP-signed `com.atproto.repo.createRecord` for
    ///    `app.bsky.graph.listitem` on the PDS.
    /// 7. **Cache Persistence**: Records the bounce in the local SQLite `bounced_users` table.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Repo`] if PDS mutation fails, or [`SkybouncerError::Database`]
    /// if cache access fails.
    #[instrument(
        skip(self, pds_client),
        fields(
            protected_did = %protected_did,
            candidate_did = %candidate_did,
            category = %category,
            confidence = %confidence
        )
    )]
    #[allow(clippy::too_many_arguments)]
    pub async fn bounce_user(
        &self,
        pds_client: &PdsRepoClient,
        protected_did: &str,
        candidate_did: &str,
        category: &ViolationCategory,
        confidence: f64,
        reason: &str,
        post_uri: &str,
    ) -> Result<Option<String>, SkybouncerError> {
        self.bounce_user_with_text(
            pds_client,
            protected_did,
            candidate_did,
            category,
            confidence,
            reason,
            post_uri,
            "",
        )
        .await
    }

    /// Bounces a violating user on the sovereign PDS, recording the offending post URI and post text in the cache.
    #[instrument(
        skip(self, pds_client),
        fields(
            protected_did = %protected_did,
            candidate_did = %candidate_did,
            category = %category,
            confidence = %confidence
        )
    )]
    #[allow(clippy::too_many_arguments)]
    pub async fn bounce_user_with_text(
        &self,
        pds_client: &PdsRepoClient,
        protected_did: &str,
        candidate_did: &str,
        category: &ViolationCategory,
        confidence: f64,
        reason: &str,
        post_uri: &str,
        post_text: &str,
    ) -> Result<Option<String>, SkybouncerError> {
        // 1. Check rubric threshold if rubric is configured
        if let Some(ref rubric) = *self.rubric.read() {
            if !rubric.meets_threshold(category, confidence) {
                debug!(
                    confidence = %confidence,
                    threshold = %rubric.sensitivity.threshold(),
                    "Confidence score below sensitivity threshold; skipping bounce"
                );
                return Ok(None);
            }
        }

        // 2. Fast cache-first short-circuit: already bounced? (Lock-free fast path)
        if self.cache.is_bounced_for(protected_did, candidate_did)? {
            debug!(
                candidate_did = %candidate_did,
                protected_did = %protected_did,
                "Candidate is already recorded as bounced for this user in cache; skipping duplicate mutation"
            );
            return Ok(None);
        }

        // 3. Acquire shard async lock for composite key to serialize concurrent bounces
        let lock_key = format!("{protected_did}:{candidate_did}");
        let shard = self.bounce_locks.shard_for(&lock_key);
        let _guard = shard.lock().await;

        // 4. Double-check cache under the lock: another task may have bounced this violator
        // while we were waiting for the lock
        if self.cache.is_bounced_for(protected_did, candidate_did)? {
            debug!(
                candidate_did = %candidate_did,
                protected_did = %protected_did,
                "Candidate was bounced by a concurrent task for this user; short-circuiting duplicate mutation"
            );
            return Ok(None);
        }

        // 5. Ensure parent moderation list exists (cache-first / synchronized)
        let list_uri = self.ensure_mod_list(pds_client, protected_did).await?;

        // 6. Construct listitem record
        let rkey = if self.dry_run {
            format!("shadow_{}", skybase::repo::generate_tid())
        } else {
            skybase::repo::generate_tid()
        };
        let now_iso = now_iso8601();
        let now_us = current_time_us();

        let (result_uri, result_cid) = if self.dry_run {
            let simulated_uri = format!("at://{protected_did}/app.bsky.graph.listitem/{rkey}");
            let simulated_cid =
                "bafyreidryrunsimulatedcid000000000000000000000000000000000".to_string();
            info!(
                violator = %candidate_did,
                protected_did = %protected_did,
                category = %category,
                confidence = %confidence,
                reason = %reason,
                post_uri = %post_uri,
                listitem_uri = %simulated_uri,
                "🛡️ [SHADOW MODE] Simulated bounce on sovereign PDS (remote mutation bypassed)"
            );
            (simulated_uri, simulated_cid)
        } else {
            let listitem = ListItemRecord::new(candidate_did, list_uri, now_iso);

            // 7. Issue DPoP-signed mutation on sovereign PDS
            let result = pds_client
                .create_record("app.bsky.graph.listitem", Some(&rkey), &listitem, true)
                .await
                .map_err(|e| {
                    SkybouncerError::Repo(format!(
                        "Failed to create listitem record for {candidate_did} on PDS: {e}"
                    ))
                })?;

            info!(
                candidate_did = %candidate_did,
                protected_did = %protected_did,
                listitem_uri = %result.uri,
                "Successfully bounced violator on sovereign PDS"
            );
            (result.uri, result.cid)
        };

        // 8. Persist to SQLite cache with compensating deletion on failure
        let bounce_record = BouncedUser {
            subject_did: candidate_did.to_string(),
            protected_did: protected_did.to_string(),
            listitem_uri: result_uri.clone(),
            listitem_rkey: rkey.clone(),
            listitem_cid: result_cid,
            category: category.to_string(),
            confidence,
            reason: reason.to_string(),
            post_uri: post_uri.to_string(),
            post_text: post_text.to_string(),
            bounced_at: now_us,
        };
        if let Err(cache_err) = self.cache.record_bounce(&bounce_record) {
            error!(
                candidate_did = %candidate_did,
                protected_did = %protected_did,
                rkey = %rkey,
                error = %cache_err,
                "Failed to record bounce in cache after PDS write succeeded; attempting compensating PDS deletion"
            );
            if !self.dry_run {
                if let Err(comp_err) = pds_client
                    .delete_record("app.bsky.graph.listitem", &rkey)
                    .await
                {
                    error!(
                        rkey = %rkey,
                        error = %comp_err,
                        "Compensating PDS deletion failed; orphaned listitem may exist"
                    );
                }
            }
            return Err(cache_err);
        }

        Ok(Some(result_uri))
    }

    /// Pardons an account by deleting its `app.bsky.graph.listitem` records from the sovereign PDS
    /// and purging the record from the local SQLite deduplication cache.
    ///
    /// Synchronizes on the composite shard lock to prevent races with concurrent bounces.
    /// Deletes all known `listitem_rkey` values associated with the subject for this protected user
    /// to guarantee zero orphaned records on the PDS.
    ///
    /// # Pipeline
    /// 1. Acquire shard async lock for `(protected_did, subject_did)`.
    /// 2. Look up all bounced `listitem_rkey` values for this protected user in the local SQLite cache.
    /// 3. If none found, returns `Ok(false)` immediately ($0 cost, 0 network calls).
    /// 4. For each recorded `rkey`, issues a DPoP-signed `com.atproto.repo.deleteRecord` to the PDS.
    /// 5. On successful deletion, purges the user from the SQLite cache.
    /// 6. Returns `Ok(true)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Repo`] if PDS deletion fails, or [`SkybouncerError::Database`]
    /// if cache access fails.
    #[instrument(skip(self, pds_client), fields(protected_did = %protected_did, subject_did = %subject_did))]
    pub async fn pardon_user(
        &self,
        pds_client: &PdsRepoClient,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        let lock_key = format!("{protected_did}:{subject_did}");
        let shard = self.bounce_locks.shard_for(&lock_key);
        let _guard = shard.lock().await;

        // 1. Look up all bounced rkeys for this protected user in local SQLite cache
        let rkeys = self
            .cache
            .get_all_bounced_rkeys_for(protected_did, subject_did)?;
        if rkeys.is_empty() {
            debug!(
                subject_did = %subject_did,
                protected_did = %protected_did,
                "Subject is not recorded in bounced users cache for this user; cannot pardon"
            );
            return Ok(false);
        }

        info!(
            subject_did = %subject_did,
            protected_did = %protected_did,
            total_rkeys = %rkeys.len(),
            "Pardoning user: deleting all associated listitems from sovereign PDS"
        );

        // 2. Delete all associated listitem records from PDS (bypassed in dry-run)
        if self.dry_run {
            info!(
                subject_did = %subject_did,
                protected_did = %protected_did,
                total_rkeys = %rkeys.len(),
                "🛡️ [SHADOW MODE] Pardoning user in shadow cache (remote PDS deletion bypassed)"
            );
        } else {
            for rkey in &rkeys {
                pds_client
                    .delete_record("app.bsky.graph.listitem", rkey)
                    .await
                    .map_err(|e| {
                        SkybouncerError::Repo(format!(
                            "Failed to delete listitem {rkey} for {subject_did} on PDS: {e}"
                        ))
                    })?;
            }
        }

        // 3. Remove entry from local SQLite cache now that PDS deletions succeeded
        let _ = self.cache.remove_bounce_for(protected_did, subject_did)?;

        info!(
            subject_did = %subject_did,
            protected_did = %protected_did,
            "Successfully pardoned user and purged from cache"
        );

        Ok(true)
    }

    /// Convenience pardon method using the client's repository owner DID.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Repo`] if PDS deletion fails, or [`SkybouncerError::Database`]
    /// if cache access fails.
    pub async fn pardon(
        &self,
        pds_client: &PdsRepoClient,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        self.pardon_user(pds_client, pds_client.did(), subject_did)
            .await
    }

    /// Checks whether the subject DID is recorded as bounced for a specific protected user in the local cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if cache access fails.
    pub fn is_bounced_for(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        self.cache.is_bounced_for(protected_did, subject_did)
    }

    /// Checks whether the subject DID is recorded as bounced in the local cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if cache access fails.
    pub fn is_bounced(&self, subject_did: &str) -> Result<bool, SkybouncerError> {
        self.cache.is_bounced(subject_did)
    }

    /// Retrieves detailed record of a bounced violator if present in the local cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if cache access fails.
    pub fn get_bounced_user(
        &self,
        subject_did: &str,
    ) -> Result<Option<BouncedUser>, SkybouncerError> {
        self.cache.get_bounced_user(subject_did)
    }

    /// Retrieves the provisioned moderation list configuration for the given protected user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if cache access fails.
    pub fn get_mod_list(&self, user_did: &str) -> Result<Option<ModListConfig>, SkybouncerError> {
        self.cache.get_mod_list(user_did)
    }

    /// Queries the PDS via `com.atproto.repo.listRecords`.
    async fn list_pds_records<T: for<'de> Deserialize<'de>>(
        &self,
        pds_client: &PdsRepoClient,
        collection: &str,
        limit: u32,
    ) -> Result<ListRecordsResponse<T>, SkybouncerError> {
        let endpoint = pds_client
            .pds_endpoint()
            .map_err(|e| SkybouncerError::Repo(format!("Failed to resolve PDS endpoint: {e}")))?
            .trim_end_matches('/');

        let mut url = url::Url::parse(&format!("{endpoint}/xrpc/com.atproto.repo.listRecords"))
            .map_err(|e| SkybouncerError::Repo(format!("Invalid PDS endpoint URL: {e}")))?;

        url.query_pairs_mut()
            .append_pair("repo", pds_client.did())
            .append_pair("collection", collection)
            .append_pair("limit", &limit.to_string());

        let resp = pds_client.http_client().get(url).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(SkybouncerError::Repo(format!(
                "listRecords failed with status {status}: {err_text}"
            )));
        }

        let parsed: ListRecordsResponse<T> = resp.json().await?;
        Ok(parsed)
    }
}

/// Computes clock-warp safe microsecond timestamp since Unix epoch.
fn current_time_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or_default())
}
