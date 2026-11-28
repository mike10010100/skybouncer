//! Sovereign ATProto moderation list manager coordinating cache-first provisioning,
//! violator bouncing, and pardons across SQLite cache and PDS repository client.

use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::Deserialize;
use skybase::repo::{ListRecordEntry, PdsRepoClient};
use tracing::{debug, error, info, instrument, warn};

use crate::classifier::{RuleRubric, ViolationCategory};
use crate::error::SkybouncerError;
use crate::modlist::cache::{BouncedUser, DeduplicationCache, ModListConfig};
use crate::modlist::sovereign_config::fetch_sovereign_config_record;
use crate::time::current_time_us;
use crate::types::{now_iso8601, ListBlockRecord, ListItemRecord, ModListRecord};

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
        &self.shards[crate::util::shard_index(key, NUM_LOCK_SHARDS)]
    }
}

impl Default for StripedAsyncLocks {
    fn default() -> Self {
        Self::new()
    }
}

/// Description of a single violation to bounce, grouping the offending account,
/// classification, and post evidence into one request value.
///
/// The optional [`post_text`](Self::post_text), [`reply_to_uri`](Self::reply_to_uri), and
/// [`expires_at`](Self::expires_at) fields are populated when interaction metadata is available
/// or a bounce duration override applies; otherwise they default to an empty body, no parent
/// reply URI, and the rubric-derived expiry.
#[derive(Debug, Clone)]
pub struct BounceRequest<'a> {
    /// DID of the protected user whose moderation list receives the entry.
    pub protected_did: &'a str,
    /// DID of the violating account being bounced.
    pub candidate_did: &'a str,
    /// Classified violation category driving the threshold check.
    pub category: &'a ViolationCategory,
    /// Model/heuristic confidence score in `[0.0, 1.0]`.
    pub confidence: f64,
    /// Human-readable reason recorded alongside the bounce.
    pub reason: &'a str,
    /// Canonical AT-URI of the offending post.
    pub post_uri: &'a str,
    /// Plaintext body of the offending post, if available.
    pub post_text: &'a str,
    /// Canonical AT-URI of the parent post being replied to, if the offending post is a reply.
    pub reply_to_uri: Option<&'a str>,
    /// Explicit expiry (microseconds since Unix epoch); falls back to the rubric duration unless
    /// explicitly set via [`Self::with_expires_at`].
    pub expires_at: Option<u64>,
    /// Optional per-tenant moderation rubric overriding the manager's default rubric.
    pub rubric: Option<&'a RuleRubric>,
    /// When `true`, skips the rubric threshold check inside [`ModListManager::bounce`].
    pub skip_threshold_check: bool,
    explicit_expiry: bool,
}

impl<'a> BounceRequest<'a> {
    /// Creates a bounce request with no post text and the rubric-derived expiry.
    #[must_use]
    pub fn new(
        protected_did: &'a str,
        candidate_did: &'a str,
        category: &'a ViolationCategory,
        confidence: f64,
        reason: &'a str,
        post_uri: &'a str,
    ) -> Self {
        Self {
            protected_did,
            candidate_did,
            category,
            confidence,
            reason,
            post_uri,
            post_text: "",
            reply_to_uri: None,
            expires_at: None,
            rubric: None,
            skip_threshold_check: false,
            explicit_expiry: false,
        }
    }

    /// Attaches the offending post body.
    #[must_use]
    pub fn with_post_text(mut self, post_text: &'a str) -> Self {
        self.post_text = post_text;
        self
    }

    /// Attaches the parent post AT-URI when the offending post is a reply.
    #[must_use]
    pub fn with_reply_to_uri(mut self, reply_to_uri: Option<&'a str>) -> Self {
        self.reply_to_uri = reply_to_uri;
        self
    }

    /// Attaches an explicit bounce expiry (microseconds since Unix epoch), or `None` for an
    /// explicitly permanent bounce regardless of the manager's default rubric duration.
    #[must_use]
    pub fn with_expires_at(mut self, expires_at: Option<u64>) -> Self {
        self.expires_at = expires_at;
        self.explicit_expiry = true;
        self
    }

    /// Attaches a per-tenant [`RuleRubric`] governing sensitivity thresholds and duration.
    #[must_use]
    pub fn with_rubric(mut self, rubric: &'a RuleRubric) -> Self {
        self.rubric = Some(rubric);
        self
    }

    /// Controls whether [`ModListManager::bounce`] skips the rubric threshold check.
    #[must_use]
    pub fn with_skip_threshold_check(mut self, skip: bool) -> Self {
        self.skip_threshold_check = skip;
        self
    }
}

/// Outcome of an automated [`ModListManager::bounce`] invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BounceOutcome {
    /// A new `app.bsky.graph.listitem` record was written on the PDS and persisted to SQLite.
    Bounced(String),
    /// The subject was already recorded as bounced for `protected_did` in SQLite.
    AlreadyBounced,
    /// The classification confidence was below the governing rubric's sensitivity threshold.
    BelowThreshold,
}

impl BounceOutcome {
    /// Returns `true` if a new bounce was executed and recorded.
    #[must_use]
    pub const fn is_bounced(&self) -> bool {
        matches!(self, Self::Bounced(_))
    }

    /// Returns the created `app.bsky.graph.listitem` AT-URI if a bounce was executed.
    #[must_use]
    pub fn listitem_uri(&self) -> Option<&str> {
        match self {
            Self::Bounced(uri) => Some(uri.as_str()),
            Self::AlreadyBounced | Self::BelowThreshold => None,
        }
    }
}

/// Outcome of an explicit user-initiated `bounce` or `perm` action on a sovereign moderation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManualBounceOutcome {
    /// A new `app.bsky.graph.listitem` record was created on the PDS and persisted in SQLite.
    Bounced {
        /// Canonical AT-URI of the newly created listitem record on the PDS.
        listitem_uri: String,
        /// Duration applied to the bounce (`Permanent` or temporary cooldown/timeout).
        duration: crate::classifier::BounceDuration,
        /// `true` if prior bounce metadata (`category`, `reason`, `post_uri`, `reply_to_uri`)
        /// was restored from `bounce_history` (e.g. re-bouncing after a pardon or expiration).
        restored_from_history: bool,
    },
    /// An active temporary bounce already existed on the PDS and was upgraded in-place to permanent.
    UpgradedToPermanent,
    /// The subject was already recorded as bounced on this moderation list.
    AlreadyBounced {
        /// `true` if the existing bounce is permanent (`expires_at.is_none()`).
        is_permanent: bool,
    },
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

    fn assert_client_matches_protected_did(
        &self,
        pds_client: &PdsRepoClient,
        protected_did: &str,
    ) -> Result<(), SkybouncerError> {
        if !self.dry_run && pds_client.did() != protected_did {
            return Err(SkybouncerError::Repo(format!(
                "PDS client DID '{}' does not match protected DID '{protected_did}'",
                pds_client.did()
            )));
        }
        Ok(())
    }

    fn validate_modlist_uri(uri: &str, protected_did: &str) -> Result<(), SkybouncerError> {
        let Some((did, collection, rkey)) = skybase::repo::split_at_uri(uri) else {
            return Err(SkybouncerError::Repo(format!(
                "Invalid moderation list AT-URI: '{uri}'"
            )));
        };
        if did != protected_did || collection != "app.bsky.graph.list" {
            return Err(SkybouncerError::Repo(format!(
                "Moderation list AT-URI '{uri}' does not belong to {protected_did}/app.bsky.graph.list"
            )));
        }
        skybase::repo::validate_rkey(rkey).map_err(|e| {
            SkybouncerError::Repo(format!("Invalid moderation list rkey in '{uri}': {e}"))
        })?;
        Ok(())
    }

    fn is_skybouncer_owned_list(&self, record: &ModListRecord) -> bool {
        if record.name == self.list_name || record.name == DEFAULT_MOD_LIST_NAME {
            return true;
        }
        record.description.as_deref().is_some_and(|desc| {
            desc.contains("[skybouncer:") || desc.contains("maintained by Skybouncer")
        })
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
    /// 4. **Remote PDS discovery**: Queries remote PDS via `com.atproto.repo.listRecords` with
    ///    cursor pagination, adopting only lists owned by Skybouncer (matching name/metadata or
    ///    persisted `mod_list_uri` in `social.skybouncer.config/self`).
    /// 5. **Provisioning**: Creates a new moderation list on the sovereign PDS via
    ///    `pds_client.create_record`, validates the resulting AT-URI, caches it, and returns it.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if `protected_did` is empty/whitespace,
    /// [`SkybouncerError::Repo`] if PDS record creation or DID ownership check fails,
    /// or [`SkybouncerError::Database`] if cache access fails.
    #[instrument(skip(self, pds_client), fields(protected_did = %protected_did))]
    pub async fn ensure_mod_list(
        &self,
        pds_client: &PdsRepoClient,
        protected_did: &str,
    ) -> Result<String, SkybouncerError> {
        let protected_did = crate::util::require_non_empty_did(protected_did, "protected_did")?;
        self.assert_client_matches_protected_did(pds_client, protected_did)?;

        // 1. Fast cache-first lookup (lock-free path)
        if let Some(config) = self.cache.get_mod_list(protected_did)? {
            Self::validate_modlist_uri(&config.list_uri, protected_did)?;
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
            Self::validate_modlist_uri(&config.list_uri, protected_did)?;
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

        let records = self
            .list_pds_records::<ModListRecord>(pds_client, protected_did, "app.bsky.graph.list")
            .await?;

        let valid_modlists: Vec<ListRecordEntry<ModListRecord>> = records
            .into_iter()
            .filter(|item| {
                item.value.is_modlist()
                    && Self::validate_modlist_uri(&item.uri, protected_did).is_ok()
            })
            .collect();

        let matched_by_metadata = valid_modlists
            .iter()
            .find(|item| self.is_skybouncer_owned_list(&item.value))
            .cloned();

        let discovered = if matched_by_metadata.is_some() {
            matched_by_metadata
        } else if !valid_modlists.is_empty() {
            let persisted_uri = fetch_sovereign_config_record(pds_client, protected_did)
                .await
                .ok()
                .flatten()
                .and_then(|(cfg, _)| cfg.mod_list_uri);
            persisted_uri.and_then(|uri| valid_modlists.into_iter().find(|item| item.uri == uri))
        } else {
            None
        };

        if let Some(item) = discovered {
            info!(
                list_uri = %item.uri,
                "Discovered existing Skybouncer moderation list on PDS; caching locally"
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
        Self::validate_modlist_uri(&result.uri, protected_did)?;

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
        let protected_did = crate::util::require_non_empty_did(protected_did, "protected_did")?;
        self.assert_client_matches_protected_did(pds_client, protected_did)?;

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
        let records = self
            .list_pds_records::<ListBlockRecord>(
                pds_client,
                protected_did,
                "app.bsky.graph.listblock",
            )
            .await?;

        for item in records {
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

    /// Bounces a violating account on the sovereign PDS, recording the offending post URI and post
    /// text in the deduplication cache.
    ///
    /// # Pipeline & Concurrency Architecture
    /// 1. **Rubric Threshold Check**: Unless `skip_threshold_check` is `true`, evaluates the
    ///    per-request rubric (falling back to `self.rubric`). If below threshold, returns
    ///    `Ok(BounceOutcome::BelowThreshold)`.
    /// 2. **Fast Deduplication Check (unlocked)**: Checks the SQLite cache to see if the user is
    ///    already bounced. If so, returns `Ok(BounceOutcome::AlreadyBounced)`.
    /// 3. **Striped Async Lock**: Synchronizes on the shard for `(protected_did, candidate_did)`.
    /// 4. **Double-Check Deduplication (under lock)**: If concurrently bounced, returns
    ///    `Ok(BounceOutcome::AlreadyBounced)`.
    /// 5. **ModList Provisioning & PDS Mutation**: Provisions the list if needed, writes the
    ///    `app.bsky.graph.listitem` record (verifying `pds_client.did() == protected_did` in live
    ///    mode), persists in SQLite, and returns `Ok(BounceOutcome::Bounced(uri))`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if `protected_did` is empty/whitespace,
    /// [`SkybouncerError::Repo`] if PDS mutation or DID ownership check fails, or
    /// [`SkybouncerError::Database`] if cache access fails.
    #[instrument(
        skip(self, pds_client, request),
        fields(
            protected_did = %request.protected_did,
            candidate_did = %request.candidate_did,
            category = %request.category,
            confidence = %request.confidence
        )
    )]
    pub async fn bounce(
        &self,
        pds_client: &PdsRepoClient,
        request: BounceRequest<'_>,
    ) -> Result<BounceOutcome, SkybouncerError> {
        let BounceRequest {
            protected_did,
            candidate_did,
            category,
            confidence,
            reason,
            post_uri,
            post_text,
            reply_to_uri,
            expires_at,
            rubric: req_rubric,
            skip_threshold_check,
            explicit_expiry,
        } = request;

        let protected_did = crate::util::require_non_empty_did(protected_did, "protected_did")?;
        self.assert_client_matches_protected_did(pds_client, protected_did)?;

        let governing_rubric: Option<RuleRubric> =
            req_rubric.cloned().or_else(|| self.rubric.read().clone());

        // 1. Check governing rubric threshold unless explicitly bypassed
        if !skip_threshold_check {
            if let Some(ref rubric) = governing_rubric {
                if !rubric.meets_threshold(category, confidence) {
                    debug!(
                        confidence = %confidence,
                        threshold = %rubric.sensitivity.threshold(),
                        "Confidence score below sensitivity threshold; skipping bounce"
                    );
                    return Ok(BounceOutcome::BelowThreshold);
                }
            }
        }

        // 2. Fast cache-first short-circuit: already bounced? (Lock-free fast path)
        if self.cache.is_bounced_for(protected_did, candidate_did)? {
            debug!(
                candidate_did = %candidate_did,
                protected_did = %protected_did,
                "Candidate is already recorded as bounced for this user in cache; skipping duplicate mutation"
            );
            return Ok(BounceOutcome::AlreadyBounced);
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
            return Ok(BounceOutcome::AlreadyBounced);
        }

        let now_us = current_time_us();
        let effective_expires_at = if explicit_expiry {
            expires_at
        } else {
            expires_at.or_else(|| {
                governing_rubric
                    .as_ref()
                    .and_then(|r| r.bounce_duration.expires_at_us(now_us))
            })
        };

        let result_uri = self
            .write_listitem_and_persist(
                pds_client,
                protected_did,
                candidate_did,
                &category.to_string(),
                confidence,
                reason,
                post_uri,
                post_text,
                reply_to_uri.map(str::to_string),
                now_us,
                effective_expires_at,
            )
            .await?;

        Ok(BounceOutcome::Bounced(result_uri))
    }

    /// Manually bounces (or permanently blocks) an account on the sovereign PDS, restoring any
    /// archived bounce metadata (`category`, `confidence`, `reason`, `post_uri`, `post_text`,
    /// `reply_to_uri`) if the account was previously pardoned or expired.
    ///
    /// Synchronizes on the composite `(protected_did, subject_did)` shard lock so concurrent
    /// live bounces, pardons, and manual DM commands cannot race.
    ///
    /// - When `upgrade_if_temp` is `true` (used by `perm <target>`) and an active temporary bounce
    ///   already exists in SQLite, upgrades it in-place to permanent (`expires_at = NULL`) without
    ///   issuing a redundant PDS write.
    /// - When the subject is not currently bounced (e.g. after `pardon` or TTL expiration),
    ///   provisions the parent moderation list if needed, creates a fresh `app.bsky.graph.listitem`
    ///   record on the PDS, and persists the bounce with `duration`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Repo`] if PDS mutation fails, or [`SkybouncerError::Database`]
    /// if SQLite cache access fails.
    #[instrument(
        skip(self, pds_client),
        fields(
            protected_did = %protected_did,
            subject_did = %subject_did,
            duration = %duration.display_label(),
            upgrade_if_temp = %upgrade_if_temp
        )
    )]
    pub async fn manual_bounce_or_perm(
        &self,
        pds_client: &PdsRepoClient,
        protected_did: &str,
        subject_did: &str,
        duration: crate::classifier::BounceDuration,
        upgrade_if_temp: bool,
    ) -> Result<ManualBounceOutcome, SkybouncerError> {
        let protected_did = crate::util::require_non_empty_did(protected_did, "protected_did")?;
        self.assert_client_matches_protected_did(pds_client, protected_did)?;
        let lock_key = format!("{protected_did}:{subject_did}");
        let shard = self.bounce_locks.shard_for(&lock_key);
        let _guard = shard.lock().await;

        if let Some(existing) = self
            .cache
            .get_bounced_user_for(protected_did, subject_did)?
        {
            if upgrade_if_temp && existing.expires_at.is_some() {
                let _ = self
                    .cache
                    .make_bounce_permanent_for(protected_did, subject_did)?;
                info!(
                    subject_did = %subject_did,
                    protected_did = %protected_did,
                    "Upgraded existing temporary bounce to permanent via manual command"
                );
                return Ok(ManualBounceOutcome::UpgradedToPermanent);
            }
            return Ok(ManualBounceOutcome::AlreadyBounced {
                is_permanent: existing.expires_at.is_none(),
            });
        }

        let archived = self
            .cache
            .get_bounce_history_for(protected_did, subject_did)?;
        let restored_from_history = archived.is_some();

        let (category, confidence, reason, post_uri, post_text, reply_to_uri) = match archived {
            Some(h) => (
                h.category,
                h.confidence,
                h.reason,
                h.post_uri,
                h.post_text,
                h.reply_to_uri,
            ),
            None => {
                let default_reason = if duration == crate::classifier::BounceDuration::Permanent {
                    "Manually blocked permanently via DM".to_string()
                } else {
                    "Manually bounced via DM".to_string()
                };
                (
                    ViolationCategory::Custom("manual_dm_block".to_string()).to_string(),
                    1.0,
                    default_reason,
                    String::new(),
                    String::new(),
                    None,
                )
            }
        };

        let now_us = current_time_us();
        let effective_expires_at = duration.expires_at_us(now_us);
        let listitem_uri = self
            .write_listitem_and_persist(
                pds_client,
                protected_did,
                subject_did,
                &category,
                confidence,
                &reason,
                &post_uri,
                &post_text,
                reply_to_uri,
                now_us,
                effective_expires_at,
            )
            .await?;

        Ok(ManualBounceOutcome::Bounced {
            listitem_uri,
            duration,
            restored_from_history,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_listitem_and_persist(
        &self,
        pds_client: &PdsRepoClient,
        protected_did: &str,
        candidate_did: &str,
        category: &str,
        confidence: f64,
        reason: &str,
        post_uri: &str,
        post_text: &str,
        reply_to_uri: Option<String>,
        now_us: u64,
        effective_expires_at: Option<u64>,
    ) -> Result<String, SkybouncerError> {
        let protected_did = crate::util::require_non_empty_did(protected_did, "protected_did")?;
        self.assert_client_matches_protected_did(pds_client, protected_did)?;
        let list_uri = self.ensure_mod_list(pds_client, protected_did).await?;

        let rkey = if self.dry_run {
            format!("shadow_{}", skybase::repo::generate_tid())
        } else {
            skybase::repo::generate_tid()
        };
        let now_iso = now_iso8601();

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
            reply_to_uri,
            bounced_at: now_us,
            expires_at: effective_expires_at,
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

        Ok(result_uri)
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
        let protected_did = crate::util::require_non_empty_did(protected_did, "protected_did")?;
        self.assert_client_matches_protected_did(pds_client, protected_did)?;
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

        // 2. Delete all associated listitem records from PDS (bypassed in dry-run),
        //    pruning each SQLite rkey incrementally as its PDS deletion succeeds or is already gone.
        if self.dry_run {
            info!(
                subject_did = %subject_did,
                protected_did = %protected_did,
                total_rkeys = %rkeys.len(),
                "🛡️ [SHADOW MODE] Pardoning user in shadow cache (remote PDS deletion bypassed)"
            );
        } else {
            for rkey in &rkeys {
                match pds_client
                    .delete_record("app.bsky.graph.listitem", rkey)
                    .await
                {
                    Ok(()) => {
                        let _ =
                            self.cache
                                .remove_bounced_rkey_for(protected_did, subject_did, rkey)?;
                    }
                    Err(e) if crate::util::is_pds_record_not_found(&e.to_string()) => {
                        warn!(
                            rkey = %rkey,
                            subject_did = %subject_did,
                            protected_did = %protected_did,
                            "Listitem record already absent on PDS during pardon; pruning SQLite rkey idempotently"
                        );
                        let _ =
                            self.cache
                                .remove_bounced_rkey_for(protected_did, subject_did, rkey)?;
                    }
                    Err(e) => {
                        return Err(SkybouncerError::Repo(format!(
                            "Failed to delete listitem {rkey} for {subject_did} on PDS: {e}"
                        )));
                    }
                }
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

    /// Upgrades a temporary bounce for `(protected_did, subject_did)` to permanent
    /// (`expires_at = NULL`).
    ///
    /// Synchronizes on the composite shard lock to prevent races with concurrent bounces or
    /// background expiration pruning. Because the `app.bsky.graph.listitem` record is already
    /// active on the user's PDS, only the SQLite cache record needs to be updated.
    ///
    /// Returns:
    /// - `Ok(Some(true))` if a temporary bounce was found and upgraded to permanent.
    /// - `Ok(Some(false))` if a bounce record exists and is already permanent.
    /// - `Ok(None)` if the subject is not recorded as bounced for `protected_did`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if `protected_did` is empty/whitespace,
    /// or [`SkybouncerError::Database`] if cache access fails.
    #[instrument(skip(self), fields(protected_did = %protected_did, subject_did = %subject_did))]
    pub async fn upgrade_bounce_to_permanent(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<Option<bool>, SkybouncerError> {
        let protected_did = crate::util::require_non_empty_did(protected_did, "protected_did")?;
        let lock_key = format!("{protected_did}:{subject_did}");
        let shard = self.bounce_locks.shard_for(&lock_key);
        let _guard = shard.lock().await;

        let res = self
            .cache
            .make_bounce_permanent_for(protected_did, subject_did)?;

        if res == Some(true) {
            info!(
                subject_did = %subject_did,
                protected_did = %protected_did,
                "Upgraded temporary bounce to permanent"
            );
        }

        Ok(res)
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

    /// Queries the PDS via `com.atproto.repo.listRecords` with cursor pagination (bounded at 20 pages).
    async fn list_pds_records<T: for<'de> Deserialize<'de>>(
        &self,
        pds_client: &PdsRepoClient,
        protected_did: &str,
        collection: &str,
    ) -> Result<Vec<ListRecordEntry<T>>, SkybouncerError> {
        const MAX_PAGES: usize = 20;
        const PAGE_LIMIT: u32 = 100;

        let mut all_records = Vec::new();
        let mut cursor: Option<String> = None;

        for _ in 0..MAX_PAGES {
            let page = pds_client
                .list_records::<T>(protected_did, collection, PAGE_LIMIT, cursor.as_deref())
                .await
                .map_err(|e| {
                    SkybouncerError::Repo(format!("listRecords failed for {collection}: {e}"))
                })?;

            all_records.extend(page.records);
            match page.cursor.filter(|c| !c.trim().is_empty()) {
                Some(next) if cursor.as_deref() != Some(next.as_str()) => {
                    cursor = Some(next);
                }
                _ => break,
            }
        }

        Ok(all_records)
    }
}
